/* MIT License
 *
 * Copyright (c) 2023 Brad House
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * SPDX-License-Identifier: MIT
 */
#include "ares_private.h"
#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#  include <sys/stat.h>
#endif
#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#ifdef HAVE_NETDB_H
#  include <netdb.h>
#endif
#ifdef HAVE_ARPA_INET_H
#  include <arpa/inet.h>
#endif
#include <time.h>

#ifdef USE_WINSOCK
#  define DATABASEPATH   "DatabasePath"
#  define WIN_PATH_HOSTS "\\hosts"
#endif

/* HOSTS FILE PROCESSING OVERVIEW
 * ==============================
 * The hosts file on the system contains static entries to be processed locally
 * rather than querying the nameserver.  Each row is an IP address followed by
 * a list of space delimited hostnames that match the ip address.  This is used
 * for both forward and reverse lookups.
 *
 * We are caching the entire parsed hosts file for performance reasons.  Some
 * files may be quite sizable and as per Issue #458 can approach 1/2MB in size,
 * and the parse overhead on a rapid succession of queries can be quite large.
 * The entries are stored in forwards and backwards hashtables so we can get
 * O(1) performance on lookup.  The file is cached until the file modification
 * timestamp changes.
 *
 * The hosts file processing is quite unique. It has to merge all related hosts
 * and ips into a single entry due to file formatting requirements.  For
 * instance take the below:
 *
 * 127.0.0.1    localhost.localdomain localhost
 * ::1          localhost.localdomain localhost
 * 192.168.1.1  host.example.com host
 * 192.168.1.5  host.example.com host
 * 2620:1234::1 host.example.com host6.example.com host6 host
 *
 * STORAGE MODEL: CACHED, ADDRESS-SCOPED ENTRIES
 * ---------------------------------------------
 * Every (hostname, address) edge that appears on any line is recorded, so no
 * "bridge" line (a line whose ip already belongs to one hostname and whose
 * hostname belongs to another) is dropped -- that dropping was Issue #1049.
 *
 * Both lookup directions return a CACHED, fully address-scoped entry directly
 * from a hashtable (no per-lookup allocation, callers do not free):
 *   - iphash:   address  -> reverse entry E_r { ips=[address],
 *               hosts=[the names that appeared on a line with that address,
 *               file-ordered] }
 *   - hosthash: hostname -> the entry to return for a forward lookup of that
 *               name.  For a single-address hostname this is simply that
 *               address's reverse entry E_r (shared, and reference counted so
 *               it is freed exactly once).  Only a multi-address hostname gets
 *               a dedicated forward entry E_f { ips=[its addresses, file
 *               order], hosts=[canonical + up to 100 address-scoped aliases] }.
 *
 * The common case -- a hostname that appears with a single address -- is wired
 * up INCREMENTALLY during the parse: the first time a hostname is seen it is
 * pointed at that line's reverse entry in hosthash directly, with no extra
 * bookkeeping.  A very large single-address file (e.g. StevenBlack/hosts, ~80k
 * names all on 0.0.0.0) therefore needs no per-hostname adjacency and no
 * finalize work at all.  Only a hostname that is later found on a SECOND
 * address is tracked (in a small temporary map of just the multi-address names
 * and their addresses); a finalize pass then replaces its hosthash entry with a
 * dedicated forward entry.  Those temporaries are discarded before returning.
 *
 * Aliases are address-scoped: exactly the hostnames that share an address with
 * the queried name, canonical first (the first such name in file order).
 */

/*! Maximum number of address-scoped aliases (beyond the canonical name) that we
 *  retain in a forward entry and emit as cnames.  Bounds the StevenBlack/hosts
 *  blocklist case where a single address can carry hundreds of thousands of
 *  names. */
#define ARES_HOSTS_MAX_ALIASES 100

/* File identity snapshot used for cache invalidation.  `valid` is set when
 * stat() succeeded; when it did not, the identity is not compared and only
 * the time-based fallback can expire the cache. */
typedef struct {
  ares_bool_t  valid;
  time_t       mtime;
  ares_int64_t size;
  ares_int64_t ino;
  ares_int64_t dev;
} ares_hosts_file_ident_t;

struct ares_hosts_file {
  time_t                  ts;
  /*! File identity as observed when the file was parsed, used to detect the
   *  file being replaced: with an older mtime (package rollback, tar -x,
   *  cp -p, backup restore) or with the same mtime but a different size,
   *  inode, or device (builds that normalize file times, or a symlink
   *  retargeted to a different filesystem). */
  ares_hosts_file_ident_t ident;
  /*! cache the filename so we know if the filename changes it automatically
   *  invalidates the cache */
  char                   *filename;
  /*! address (normalized str) -> cached reverse entry (ares_hosts_entry_t).
   *  Owns the entry via ares_hosts_entry_destroy_cb (reference counted). */
  ares_htable_strvp_t    *iphash;
  /*! hostname (str) -> cached entry to return for a forward lookup of that name
   *  (ares_hosts_entry_t).  May be the same object as an iphash reverse entry
   *  (single-address hostname) or a dedicated forward entry (multi-address).
   *  Owns the entry via ares_hosts_entry_destroy_cb (reference counted). */
  ares_htable_strvp_t    *hosthash;
};

struct ares_hosts_entry {
  size_t        refcnt; /*! Entries may be shared between iphash and hosthash,
                         *  so they are reference counted. */
  ares_llist_t *ips;
  ares_llist_t *hosts;
};

const void *ares_dns_pton(const char *ipaddr, struct ares_addr *addr,
                          size_t *out_len)
{
  const void *ptr     = NULL;
  size_t      ptr_len = 0;

  if (ipaddr == NULL || addr == NULL || out_len == NULL) {
    return NULL; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *out_len = 0;

  if (addr->family == AF_INET &&
      ares_inet_pton(AF_INET, ipaddr, &addr->addr.addr4) > 0) {
    ptr     = &addr->addr.addr4;
    ptr_len = sizeof(addr->addr.addr4);
  } else if (addr->family == AF_INET6 &&
             ares_inet_pton(AF_INET6, ipaddr, &addr->addr.addr6) > 0) {
    ptr     = &addr->addr.addr6;
    ptr_len = sizeof(addr->addr.addr6);
  } else if (addr->family == AF_UNSPEC) {
    if (ares_inet_pton(AF_INET, ipaddr, &addr->addr.addr4) > 0) {
      addr->family = AF_INET;
      ptr          = &addr->addr.addr4;
      ptr_len      = sizeof(addr->addr.addr4);
    } else if (ares_inet_pton(AF_INET6, ipaddr, &addr->addr.addr6) > 0) {
      addr->family = AF_INET6;
      ptr          = &addr->addr.addr6;
      ptr_len      = sizeof(addr->addr.addr6);
    }
  }

  *out_len = ptr_len;
  return ptr;
}

static ares_bool_t ares_normalize_ipaddr(const char *ipaddr, char *out,
                                         size_t out_len)
{
  struct ares_addr data;
  const void      *addr;
  size_t           addr_len = 0;

  memset(&data, 0, sizeof(data));
  data.family = AF_UNSPEC;

  addr = ares_dns_pton(ipaddr, &data, &addr_len);
  if (addr == NULL) {
    return ARES_FALSE;
  }

  if (!ares_inet_ntop(data.family, addr, out, (ares_socklen_t)out_len)) {
    return ARES_FALSE; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  return ARES_TRUE;
}

static void ares_hosts_entry_destroy(ares_hosts_entry_t *entry)
{
  if (entry == NULL) {
    return;
  }

  /* Honor reference counting: only free once the last reference goes away */
  if (entry->refcnt > 0) {
    entry->refcnt--;
  }
  if (entry->refcnt > 0) {
    return;
  }

  ares_llist_destroy(entry->hosts);
  ares_llist_destroy(entry->ips);
  ares_free(entry);
}

/* iphash/hosthash value destructor: values are (refcounted) entries */
static void ares_hosts_entry_destroy_cb(void *e)
{
  ares_hosts_entry_destroy(e);
}

/* Temporary forward-adjacency htable value destructor: each value is an
 * ares_llist_t of ip strings */
static void ares_hosts_list_destroy_cb(void *arg)
{
  ares_llist_destroy(arg);
}

void ares_hosts_file_destroy(ares_hosts_file_t *hf)
{
  if (hf == NULL) {
    return;
  }

  ares_free(hf->filename);
  ares_htable_strvp_destroy(hf->hosthash);
  ares_htable_strvp_destroy(hf->iphash);
  ares_free(hf);
}

static ares_hosts_file_t *ares_hosts_file_create(const char *filename)
{
  ares_hosts_file_t *hf = ares_malloc_zero(sizeof(*hf));
  if (hf == NULL) {
    goto fail;
  }

  hf->ts = time(NULL);

  hf->filename = ares_strdup(filename);
  if (hf->filename == NULL) {
    goto fail;
  }

  hf->iphash = ares_htable_strvp_create(ares_hosts_entry_destroy_cb);
  if (hf->iphash == NULL) {
    goto fail;
  }

  hf->hosthash = ares_htable_strvp_create(ares_hosts_entry_destroy_cb);
  if (hf->hosthash == NULL) {
    goto fail;
  }

  return hf;

fail:
  ares_hosts_file_destroy(hf);
  return NULL;
}

/* Case-insensitive membership test for an ip/host string list */
static ares_bool_t ares_hosts_strlist_contains(ares_llist_t *list,
                                               const char   *ipaddr)
{
  ares_llist_node_t *node;

  for (node = ares_llist_node_first(list); node != NULL;
       node = ares_llist_node_next(node)) {
    if (ares_strcaseeq(ares_llist_node_val(node), ipaddr)) {
      return ARES_TRUE;
    }
  }

  return ARES_FALSE;
}

/* Append a string copy to a list, returning the stored copy (or NULL on OOM) */
static char *ares_hosts_list_append_strdup(ares_llist_t *list, const char *str)
{
  char *tmp = ares_strdup(str);
  if (tmp == NULL) {
    return NULL; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  if (ares_llist_insert_last(list, tmp) == NULL) {
    ares_free(tmp); /* LCOV_EXCL_LINE: OutOfMemory */
    return NULL;    /* LCOV_EXCL_LINE: OutOfMemory */
  }
  return tmp;
}

/* Fetch (creating if needed) the cached reverse entry for 'ipaddr'.  A reverse
 * entry is { refcnt=1, ips=[ipaddr], hosts=[] } and is owned by iphash. */
static ares_status_t ares_hosts_reverse_entry(ares_hosts_file_t   *hosts,
                                              const char          *ipaddr,
                                              ares_hosts_entry_t **out)
{
  ares_hosts_entry_t *rev = ares_htable_strvp_get_direct(hosts->iphash, ipaddr);

  if (rev != NULL) {
    *out = rev;
    return ARES_SUCCESS;
  }

  rev = ares_malloc_zero(sizeof(*rev));
  if (rev == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  rev->refcnt = 1;
  rev->ips    = ares_llist_create(ares_free);
  rev->hosts  = ares_llist_create(ares_free);
  if (rev->ips == NULL || rev->hosts == NULL) {
    ares_hosts_entry_destroy(rev); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (ares_hosts_list_append_strdup(rev->ips, ipaddr) == NULL) {
    ares_hosts_entry_destroy(rev); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  if (!ares_htable_strvp_insert(hosts->iphash, ipaddr, rev)) {
    ares_hosts_entry_destroy(rev); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  *out = rev;
  return ARES_SUCCESS;
}

/*! entry represents a single parsed line (one ip, its hostnames).  It is always
 *  invalidated (destroyed) upon calling this function, even on error.
 *
 *  Each new (hostname, ipaddress) edge is appended to the address's reverse
 *  entry in iphash.  A hostname's first sighting is wired directly into
 *  hosthash as a shared reference to that reverse entry (the single-address
 *  fast path).  Only when a hostname is later found on a SECOND address is it
 *  tracked in the small temporary 'multi' map (hostname -> its ip strings) and
 *  appended to 'multi_names'; hosthash keeps pointing at the shared reverse
 *  entry until the finalize pass replaces it. */
static ares_status_t ares_hosts_file_add(ares_hosts_file_t   *hosts,
                                         ares_htable_strvp_t *multi,
                                         ares_llist_t        *multi_names,
                                         ares_hosts_entry_t  *entry)
{
  const char        *ipaddr = ares_llist_first_val(entry->ips);
  ares_llist_node_t *node;
  ares_status_t      status = ARES_SUCCESS;

  for (node = ares_llist_node_first(entry->hosts); node != NULL;
       node = ares_llist_node_next(node)) {
    const char         *host = ares_llist_node_val(node);
    ares_hosts_entry_t *rev;
    ares_hosts_entry_t *cur;
    ares_llist_t       *m;

    /* Reverse entry for this line's ip */
    status = ares_hosts_reverse_entry(hosts, ipaddr, &rev);
    if (status != ARES_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cur = ares_htable_strvp_get_direct(hosts->hosthash, host);

    if (cur == NULL) {
      /* First sighting of host: assume single-address, share this reverse
       * entry.  The (host, ip) edge is new. */
      if (!ares_htable_strvp_insert(hosts->hosthash, host, rev)) {
        status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      rev->refcnt++;
      if (ares_hosts_list_append_strdup(rev->hosts, host) == NULL) {
        status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      continue;
    }

    if (cur == rev) {
      /* host already recorded on this same ip -> duplicate edge, skip */
      continue;
    }

    /* host is (or is becoming) multi-address: cur is the reverse entry of its
     * first address, which differs from this line's ip. */
    m = ares_htable_strvp_get_direct(multi, host);
    if (m == NULL) {
      /* Second distinct address: start tracking host's address list.  Seed it
       * with its existing first address followed by this one. */
      const char *first_ip = ares_llist_first_val(cur->ips);
      char       *hostcopy;

      m = ares_llist_create(ares_free);
      if (m == NULL) {
        status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (ares_hosts_list_append_strdup(m, first_ip) == NULL ||
          ares_hosts_list_append_strdup(m, ipaddr) == NULL) {
        ares_llist_destroy(m); /* LCOV_EXCL_LINE: OutOfMemory */
        status = ARES_ENOMEM;  /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (!ares_htable_strvp_insert(multi, host, m)) {
        ares_llist_destroy(m); /* LCOV_EXCL_LINE: OutOfMemory */
        status = ARES_ENOMEM;  /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;             /* LCOV_EXCL_LINE: OutOfMemory */
      }

      /* The (host, ip) edge is new; append to this ip's reverse entry and
       * remember host (by reference to the persistent copy) for finalize. */
      hostcopy = ares_hosts_list_append_strdup(rev->hosts, host);
      if (hostcopy == NULL) {
        status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      if (ares_llist_insert_last(multi_names, hostcopy) == NULL) {
        status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
        goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
      continue;
    }

    /* Already multi-address.  Record the edge if this ip is new for host. */
    if (ares_hosts_strlist_contains(m, ipaddr)) {
      continue;
    }
    if (ares_hosts_list_append_strdup(m, ipaddr) == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
    if (ares_hosts_list_append_strdup(rev->hosts, host) == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

done:
  ares_hosts_entry_destroy(entry);
  return status;
}

/* Build the forward entry for a hostname that appeared with 2+ addresses:
 * { refcnt=1, ips=[its addresses, file order],
 *   hosts=[canonical + up to 100 address-scoped aliases] }. */
static ares_status_t ares_hosts_build_forward_entry(ares_hosts_file_t   *hosts,
                                                    ares_llist_t        *flist,
                                                    ares_hosts_entry_t **out)
{
  ares_hosts_entry_t *ent;
  ares_llist_node_t  *ipnode;

  *out = NULL;

  ent = ares_malloc_zero(sizeof(*ent));
  if (ent == NULL) {
    return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
  }
  ent->refcnt = 1;
  ent->ips    = ares_llist_create(ares_free);
  ent->hosts  = ares_llist_create(ares_free);
  if (ent->ips == NULL || ent->hosts == NULL) {
    ares_hosts_entry_destroy(ent); /* LCOV_EXCL_LINE: OutOfMemory */
    return ARES_ENOMEM;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  /* ips = this hostname's addresses, in file order */
  for (ipnode = ares_llist_node_first(flist); ipnode != NULL;
       ipnode = ares_llist_node_next(ipnode)) {
    if (ares_hosts_list_append_strdup(ent->ips, ares_llist_node_val(ipnode)) ==
        NULL) {
      ares_hosts_entry_destroy(ent); /* LCOV_EXCL_LINE: OutOfMemory */
      return ARES_ENOMEM;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  /* hosts = address-scoped alias list, canonical first.  Iterate the addresses
   * in order; for each, iterate the reverse entry's hostnames in order,
   * appending each name not already present (case-insensitive).  Cap at 101
   * (canonical + 100 aliases) to bound the StevenBlack blocklist case. */
  for (ipnode = ares_llist_node_first(ent->ips); ipnode != NULL;
       ipnode = ares_llist_node_next(ipnode)) {
    const char         *ip  = ares_llist_node_val(ipnode);
    ares_hosts_entry_t *rev = ares_htable_strvp_get_direct(hosts->iphash, ip);
    ares_llist_node_t  *nnode;

    /* Every ip in ent->ips was recorded during parse and so has an iphash
     * entry; nothing removes from iphash.  Guard anyway so a future change that
     * could drop an entry degrades to a lookup miss rather than a NULL deref.
     */
    if (rev == NULL) {
      continue; /* LCOV_EXCL_LINE: DefensiveCoding */
    }

    if (ares_llist_len(ent->hosts) >= ARES_HOSTS_MAX_ALIASES + 1) {
      break; /* LCOV_EXCL_LINE: FallbackCode */
    }

    for (nnode = ares_llist_node_first(rev->hosts); nnode != NULL;
         nnode = ares_llist_node_next(nnode)) {
      const char *nm = ares_llist_node_val(nnode);

      if (ares_hosts_strlist_contains(ent->hosts, nm)) {
        continue;
      }
      if (ares_llist_len(ent->hosts) >= ARES_HOSTS_MAX_ALIASES + 1) {
        break; /* LCOV_EXCL_LINE: FallbackCode */
      }

      if (ares_hosts_list_append_strdup(ent->hosts, nm) == NULL) {
        ares_hosts_entry_destroy(ent); /* LCOV_EXCL_LINE: OutOfMemory */
        return ARES_ENOMEM;            /* LCOV_EXCL_LINE: OutOfMemory */
      }
    }
  }

  *out = ent;
  return ARES_SUCCESS;
}

/* After all lines are parsed, give each multi-address hostname its own
 * dedicated forward entry.  During the parse hosthash[name] was left pointing
 * at the shared reverse entry of the name's first address; inserting the
 * forward entry over that key invokes the value destructor on the old shared
 * entry (dropping its reference), cleanly un-sharing it. */
static ares_status_t ares_hosts_finalize(ares_hosts_file_t   *hosts,
                                         ares_htable_strvp_t *multi,
                                         ares_llist_t        *multi_names)
{
  ares_llist_node_t *node;

  for (node = ares_llist_node_first(multi_names); node != NULL;
       node = ares_llist_node_next(node)) {
    const char         *name = ares_llist_node_val(node);
    ares_llist_t       *m    = ares_htable_strvp_get_direct(multi, name);
    ares_hosts_entry_t *ent;
    ares_status_t       status;

    status = ares_hosts_build_forward_entry(hosts, m, &ent);
    if (status != ARES_SUCCESS) {
      return status; /* LCOV_EXCL_LINE: OutOfMemory */
    }

    if (!ares_htable_strvp_insert(hosts->hosthash, name, ent)) {
      ares_hosts_entry_destroy(ent); /* LCOV_EXCL_LINE: OutOfMemory */
      return ARES_ENOMEM;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  return ARES_SUCCESS;
}

static ares_bool_t ares_hosts_entry_isdup(ares_hosts_entry_t *entry,
                                          const char         *host)
{
  ares_llist_node_t *node;

  for (node = ares_llist_node_first(entry->hosts); node != NULL;
       node = ares_llist_node_next(node)) {
    const char *myhost = ares_llist_node_val(node);
    if (ares_strcaseeq(myhost, host)) {
      return ARES_TRUE;
    }
  }

  return ARES_FALSE;
}

static ares_status_t ares_parse_hosts_hostnames(ares_buf_t         *buf,
                                                ares_hosts_entry_t *entry)
{
  entry->hosts = ares_llist_create(ares_free);
  if (entry->hosts == NULL) {
    return ARES_ENOMEM;
  }

  /* Parse hostnames and aliases */
  while (ares_buf_len(buf)) {
    char          hostname[256];
    char         *temp;
    ares_status_t status;
    unsigned char comment = '#';

    ares_buf_consume_whitespace(buf, ARES_FALSE);

    if (ares_buf_len(buf) == 0) {
      break;
    }

    /* See if it is a comment, if so stop processing */
    if (ares_buf_begins_with(buf, &comment, 1)) {
      break;
    }

    ares_buf_tag(buf);

    /* Must be at end of line */
    if (ares_buf_consume_nonwhitespace(buf) == 0) {
      break;
    }

    status = ares_buf_tag_fetch_string(buf, hostname, sizeof(hostname),
                                       ARES_BUF_CHARSET_ASCII);
    if (status != ARES_SUCCESS) {
      /* Bad entry, just ignore as long as its not the first.  If its the first,
       * it must be valid */
      if (ares_llist_len(entry->hosts) == 0) {
        return ARES_EBADSTR;
      }

      continue;
    }

    /* Validate it is a valid hostname characterset */
    if (!ares_is_hostname(hostname)) {
      continue;
    }

    /* Don't add a duplicate to the same entry */
    if (ares_hosts_entry_isdup(entry, hostname)) {
      continue;
    }

    /* Add to list */
    temp = ares_strdup(hostname);
    if (temp == NULL) {
      return ARES_ENOMEM;
    }

    if (ares_llist_insert_last(entry->hosts, temp) == NULL) {
      ares_free(temp);
      return ARES_ENOMEM;
    }
  }

  /* Must have at least 1 entry */
  if (ares_llist_len(entry->hosts) == 0) {
    return ARES_EBADSTR;
  }

  return ARES_SUCCESS;
}

static ares_status_t ares_parse_hosts_ipaddr(ares_buf_t          *buf,
                                             ares_hosts_entry_t **entry_out)
{
  char                addr[INET6_ADDRSTRLEN];
  char               *temp;
  ares_hosts_entry_t *entry = NULL;
  ares_status_t       status;

  *entry_out = NULL;

  ares_buf_tag(buf);
  ares_buf_consume_nonwhitespace(buf);
  status =
    ares_buf_tag_fetch_string(buf, addr, sizeof(addr), ARES_BUF_CHARSET_ASCII);
  if (status != ARES_SUCCESS) {
    return status;
  }

  /* Validate and normalize the ip address format */
  if (!ares_normalize_ipaddr(addr, addr, sizeof(addr))) {
    return ARES_EBADSTR;
  }

  entry = ares_malloc_zero(sizeof(*entry));
  if (entry == NULL) {
    return ARES_ENOMEM;
  }

  entry->ips = ares_llist_create(ares_free);
  if (entry->ips == NULL) {
    ares_hosts_entry_destroy(entry);
    return ARES_ENOMEM;
  }

  temp = ares_strdup(addr);
  if (temp == NULL) {
    ares_hosts_entry_destroy(entry);
    return ARES_ENOMEM;
  }

  if (ares_llist_insert_first(entry->ips, temp) == NULL) {
    ares_free(temp);
    ares_hosts_entry_destroy(entry);
    return ARES_ENOMEM;
  }

  *entry_out = entry;

  return ARES_SUCCESS;
}

static void ares_hosts_file_ident(const char              *filename,
                                  ares_hosts_file_ident_t *ident)
{
  memset(ident, 0, sizeof(*ident));

#ifdef HAVE_STAT
  {
    struct stat st;
    if (stat(filename, &st) == 0) {
      ident->valid = ARES_TRUE;
      ident->mtime = st.st_mtime;
      ident->size  = (ares_int64_t)st.st_size;
      ident->ino   = (ares_int64_t)st.st_ino;
      ident->dev   = (ares_int64_t)st.st_dev;
    }
  }
#elif defined(_WIN32)
  {
    struct _stat st;
    if (_stat(filename, &st) == 0) {
      ident->valid = ARES_TRUE;
      ident->mtime = st.st_mtime;
      ident->size  = (ares_int64_t)st.st_size;
      ident->dev   = (ares_int64_t)st.st_dev;
      /* st_ino from _stat() is not meaningful on Windows; leave 0, and
       * comparing 0 to 0 is harmless. */
    }
  }
#else
  (void)filename;
#endif
}

static ares_status_t ares_parse_hosts(const char         *filename,
                                      ares_hosts_file_t **out)
{
  ares_buf_t             *buf    = NULL;
  ares_status_t           status = ARES_EBADRESP;
  ares_hosts_file_t      *hf     = NULL;
  ares_hosts_entry_t     *entry  = NULL;
  ares_hosts_file_ident_t ident;
  /* Small temporaries tracking ONLY multi-address hostnames: their ip lists
   * (multi) and the order they became multi (multi_names, holding references,
   * not owned, to hostname copies that live in the reverse entries).  For a
   * single-address file these stay empty.  Discarded before returning. */
  ares_htable_strvp_t    *multi       = NULL;
  ares_llist_t           *multi_names = NULL;

  *out = NULL;

  /* Capture the file identity BEFORE reading the contents.  If the file is
   * replaced between the stat and the read, the cached identity describes a
   * file at least as old as the contents we parsed, so the worst case is an
   * extra re-read; the cache can never be held past a replacement. */
  ares_hosts_file_ident(filename, &ident);

  buf = ares_buf_create();
  if (buf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  status = ares_buf_load_file(filename, buf);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  hf = ares_hosts_file_create(filename);
  if (hf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }

  hf->ident = ident;

  multi       = ares_htable_strvp_create(ares_hosts_list_destroy_cb);
  multi_names = ares_llist_create(NULL);
  if (multi == NULL || multi_names == NULL) {
    status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
  }

  while (ares_buf_len(buf)) {
    unsigned char comment = '#';

    /* -- Start of new line here -- */

    /* Consume any leading whitespace */
    ares_buf_consume_whitespace(buf, ARES_FALSE);

    if (ares_buf_len(buf) == 0) {
      break;
    }

    /* See if it is a comment, if so, consume remaining line */
    if (ares_buf_begins_with(buf, &comment, 1)) {
      ares_buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Pull off ip address */
    status = ares_parse_hosts_ipaddr(buf, &entry);
    if (status == ARES_ENOMEM) {
      goto done;
    }
    if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares_buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Parse of the hostnames */
    status = ares_parse_hosts_hostnames(buf, entry);
    if (status == ARES_ENOMEM) {
      goto done;
    } else if (status != ARES_SUCCESS) {
      /* Bad line, consume and go onto next */
      ares_hosts_entry_destroy(entry);
      entry = NULL;
      ares_buf_consume_line(buf, ARES_TRUE);
      continue;
    }

    /* Record this line's edges (reverse entries + single-address sharing;
     * multi-address names accumulate in multi/multi_names) */
    status = ares_hosts_file_add(hf, multi, multi_names, entry);
    entry  = NULL; /* is always invalidated by this function, even on error */
    if (status != ARES_SUCCESS) {
      goto done;
    }

    /* Go to next line */
    ares_buf_consume_line(buf, ARES_TRUE);
  }

  /* Give each multi-address hostname its dedicated forward entry */
  status = ares_hosts_finalize(hf, multi, multi_names);
  if (status != ARES_SUCCESS) {
    goto done; /* LCOV_EXCL_LINE: OutOfMemory */
  }

  status = ARES_SUCCESS;

done:
  ares_hosts_entry_destroy(entry);
  ares_llist_destroy(multi_names);
  ares_htable_strvp_destroy(multi);
  ares_buf_destroy(buf);
  if (status != ARES_SUCCESS) {
    ares_hosts_file_destroy(hf);
  } else {
    *out = hf;
  }
  return status;
}

static ares_bool_t ares_hosts_expired(const char              *filename,
                                      const ares_hosts_file_t *hf)
{
  ares_hosts_file_ident_t ident;

  ares_hosts_file_ident(filename, &ident);

  if (hf == NULL) {
    return ARES_TRUE;
  }

  /* If filenames are different, its expired */
  if (!ares_strcaseeq(hf->filename, filename)) {
    return ARES_TRUE;
  }

  /* The file was replaced, possibly with an older mtime (package rollback,
   * tar -x, cp -p, backup restore) or with the same mtime but a different
   * size, inode, or device (builds that normalize file times, or a symlink
   * retargeted to a different filesystem).  Compare the identity only when
   * it could be read. */
  if (ident.valid &&
      (!hf->ident.valid || ident.mtime != hf->ident.mtime ||
       ident.size != hf->ident.size || ident.ino != hf->ident.ino ||
       ident.dev != hf->ident.dev)) {
    return ARES_TRUE;
  }

  /* Expire every 60s if we can't get a time */
  if (!ident.valid) {
    ident.mtime =
      time(NULL) - 60; /* LCOV_EXCL_LINE: only on systems without stat() */
  }

  if (hf->ts <= ident.mtime) {
    return ARES_TRUE;
  }

  return ARES_FALSE;
}

static ares_status_t ares_hosts_path(const ares_channel_t *channel,
                                     ares_bool_t use_env, char **path)
{
  char *path_hosts = NULL;

  *path = NULL;

  if (channel->hosts_path) {
    path_hosts = ares_strdup(channel->hosts_path);
    if (!path_hosts) {
      return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (use_env) {
    if (path_hosts) {
      ares_free(path_hosts);
    }

    path_hosts = ares_strdup(getenv("CARES_HOSTS"));
    if (!path_hosts) {
      return ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  if (!path_hosts) {
#if defined(USE_WINSOCK)
    char  PATH_HOSTS[MAX_PATH];
    char  tmp[MAX_PATH];
    HKEY  hkeyHosts;
    DWORD dwLength;

    memset(PATH_HOSTS, 0, sizeof(PATH_HOSTS));
    memset(tmp, 0, sizeof(tmp));
    dwLength = (DWORD)sizeof(tmp);

    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, WIN_NS_NT_KEY, 0, KEY_READ,
                      &hkeyHosts) != ERROR_SUCCESS) {
      return ARES_ENOTFOUND;
    }
    if (RegQueryValueExA(hkeyHosts, DATABASEPATH, NULL, NULL, (LPBYTE)tmp,
                         &dwLength) != ERROR_SUCCESS ||
        dwLength == 0) {
      RegCloseKey(hkeyHosts);
      return ARES_ENOTFOUND;
    }
    RegCloseKey(hkeyHosts);

    /* Registry REG_SZ data is not guaranteed to be null-terminated */
    tmp[sizeof(tmp) - 1] = '\0';
    if (ExpandEnvironmentStringsA(tmp, PATH_HOSTS, (DWORD)sizeof(PATH_HOSTS)) ==
        0) {
      return ARES_ENOTFOUND;
    }
    if (strlen(PATH_HOSTS) + strlen(WIN_PATH_HOSTS) >= sizeof(PATH_HOSTS)) {
      return ARES_ENOTFOUND;
    }
    strcat(PATH_HOSTS, WIN_PATH_HOSTS);
#elif defined(WATT32)
    const char *PATH_HOSTS = _w32_GetHostsFile();

    if (!PATH_HOSTS) {
      return ARES_ENOTFOUND;
    }
#endif
    path_hosts = ares_strdup(PATH_HOSTS);
    if (!path_hosts) {
      return ARES_ENOMEM;
    }
  }

  *path = path_hosts;
  return ARES_SUCCESS;
}

static ares_status_t ares_hosts_update(ares_channel_t *channel,
                                       ares_bool_t     use_env)
{
  ares_status_t status;
  char         *filename = NULL;

  status = ares_hosts_path(channel, use_env, &filename);
  if (status != ARES_SUCCESS) {
    return status;
  }

  if (!ares_hosts_expired(filename, channel->hf)) {
    ares_free(filename);
    return ARES_SUCCESS;
  }

  ares_hosts_file_destroy(channel->hf);
  channel->hf = NULL;

  status = ares_parse_hosts(filename, &channel->hf);
  ares_free(filename);
  return status;
}

ares_status_t ares_hosts_search_ipaddr(ares_channel_t *channel,
                                       ares_bool_t use_env, const char *ipaddr,
                                       const ares_hosts_entry_t **entry)
{
  ares_status_t status;
  char          addr[INET6_ADDRSTRLEN];

  *entry = NULL;

  status = ares_hosts_update(channel, use_env);
  if (status != ARES_SUCCESS) {
    return status;
  }

  if (channel->hf == NULL) {
    return ARES_ENOTFOUND; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (!ares_normalize_ipaddr(ipaddr, addr, sizeof(addr))) {
    return ARES_EBADNAME;
  }

  /* Cached, address-scoped reverse entry (caller does not free) */
  *entry = ares_htable_strvp_get_direct(channel->hf->iphash, addr);
  if (*entry == NULL) {
    return ARES_ENOTFOUND;
  }

  return ARES_SUCCESS;
}

ares_status_t ares_hosts_search_host(ares_channel_t *channel,
                                     ares_bool_t use_env, const char *host,
                                     const ares_hosts_entry_t **entry)
{
  ares_status_t status;

  *entry = NULL;

  status = ares_hosts_update(channel, use_env);
  if (status != ARES_SUCCESS) {
    return status;
  }

  if (channel->hf == NULL) {
    return ARES_ENOTFOUND; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  /* Cached, address-scoped forward entry (caller does not free) */
  *entry = ares_htable_strvp_get_direct(channel->hf->hosthash, host);
  if (*entry == NULL) {
    return ARES_ENOTFOUND;
  }

  return ARES_SUCCESS;
}

static ares_status_t
  ares_hosts_ai_append_cnames(const ares_hosts_entry_t    *entry,
                              struct ares_addrinfo_cname **cnames_out)
{
  struct ares_addrinfo_cname *cname       = NULL;
  struct ares_addrinfo_cname *cnames      = NULL;
  const char                 *primaryhost = ares_llist_first_val(entry->hosts);
  ares_llist_node_t          *node;
  ares_status_t               status;
  size_t                      cnt = 0;

  /* Canonical name is the first host (in file order); aliases are the rest. */
  node = ares_llist_node_next(ares_llist_node_first(entry->hosts));

  while (node != NULL) {
    const char *host = ares_llist_node_val(node);

    /* Cap aliases (ARES_HOSTS_MAX_ALIASES); some people use
     * https://github.com/StevenBlack/hosts and we don't need 200k+ aliases */
    cnt++;
    if (cnt > ARES_HOSTS_MAX_ALIASES) {
      break; /* LCOV_EXCL_LINE: FallbackCode */
    }

    cname = ares_append_addrinfo_cname(&cnames);
    if (cname == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->alias = ares_strdup(host);
    if (cname->alias == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->name = ares_strdup(primaryhost);
    if (cname->name == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    node = ares_llist_node_next(node);
  }

  /* No entries, add only primary */
  if (cnames == NULL) {
    cname = ares_append_addrinfo_cname(&cnames);
    if (cname == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }

    cname->name = ares_strdup(primaryhost);
    if (cname->name == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    ares_freeaddrinfo_cnames(cnames); /* LCOV_EXCL_LINE: DefensiveCoding */
    return status;                    /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  *cnames_out = cnames;
  return ARES_SUCCESS;
}

ares_status_t ares_hosts_entry_to_addrinfo(const ares_hosts_entry_t *entry,
                                           const char *name, int family,
                                           unsigned short        port,
                                           ares_bool_t           want_cnames,
                                           struct ares_addrinfo *ai)
{
  ares_status_t               status  = ARES_ENOTFOUND;
  struct ares_addrinfo_cname *cnames  = NULL;
  struct ares_addrinfo_node  *ainodes = NULL;
  ares_llist_node_t          *node;

  switch (family) {
    case AF_INET:
    case AF_INET6:
    case AF_UNSPEC:
      break;
    default:                  /* LCOV_EXCL_LINE: DefensiveCoding */
      return ARES_EBADFAMILY; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  if (name != NULL) {
    ares_free(ai->name);
    ai->name = ares_strdup(name);
    if (ai->name == NULL) {
      status = ARES_ENOMEM; /* LCOV_EXCL_LINE: OutOfMemory */
      goto done;            /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }

  for (node = ares_llist_node_first(entry->ips); node != NULL;
       node = ares_llist_node_next(node)) {
    struct ares_addr addr;
    const void      *ptr     = NULL;
    size_t           ptr_len = 0;
    const char      *ipaddr  = ares_llist_node_val(node);

    memset(&addr, 0, sizeof(addr));
    addr.family = family;
    ptr         = ares_dns_pton(ipaddr, &addr, &ptr_len);

    if (ptr == NULL) {
      continue;
    }

    status = ares_append_ai_node(addr.family, port, 0, ptr, &ainodes);
    if (status != ARES_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  /* Might be ARES_ENOTFOUND here if no ips matched requested address family */
  if (status != ARES_SUCCESS) {
    goto done;
  }

  if (want_cnames) {
    status = ares_hosts_ai_append_cnames(entry, &cnames);
    if (status != ARES_SUCCESS) {
      goto done; /* LCOV_EXCL_LINE: DefensiveCoding */
    }
  }

  status = ARES_SUCCESS;

done:
  if (status != ARES_SUCCESS) {
    /* LCOV_EXCL_START: defensive coding */
    ares_freeaddrinfo_cnames(cnames);
    ares_freeaddrinfo_nodes(ainodes);
    ares_free(ai->name);
    ai->name = NULL;
    return status;
    /* LCOV_EXCL_STOP */
  }
  ares_addrinfo_cat_cnames(&ai->cnames, cnames);
  ares_addrinfo_cat_nodes(&ai->nodes, ainodes);

  return status;
}

ares_status_t ares_hosts_entry_to_hostent(const ares_hosts_entry_t *entry,
                                          int family, struct hostent **hostent)
{
  ares_status_t         status;
  struct ares_addrinfo *ai = ares_malloc_zero(sizeof(*ai));

  *hostent = NULL;

  if (ai == NULL) {
    return ARES_ENOMEM;
  }

  status = ares_hosts_entry_to_addrinfo(entry, NULL, family, 0, ARES_TRUE, ai);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  status = ares_addrinfo2hostent(ai, family, hostent);
  if (status != ARES_SUCCESS) {
    goto done;
  }

done:
  ares_freeaddrinfo(ai);
  if (status != ARES_SUCCESS) {
    ares_free_hostent(*hostent);
    *hostent = NULL;
  }

  return status;
}
