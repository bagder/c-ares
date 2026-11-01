/* MIT License
 *
 * Copyright (c) 1998 Massachusetts Institute of Technology
 * Copyright (c) The c-ares project and its contributors
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

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif
#include "ares_nameser.h"

/* https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00 */
static ares_status_t ares_apply_dns0x20(ares_channel_t    *channel,
                                        ares_dns_record_t *dnsrec)
{
  ares_status_t status = ARES_SUCCESS;
  const char   *name   = NULL;
  char          dns0x20name[256];
  unsigned char randdata[256 / 8];
  size_t        len;
  size_t        remaining_bits;
  size_t        total_bits;
  size_t        i;

  status = ares_dns_record_query_get(dnsrec, 0, &name, NULL, NULL);
  if (status != ARES_SUCCESS) {
    goto done;
  }

  len = ares_strlen(name);
  if (len == 0) {
    return ARES_SUCCESS;
  }

  if (len >= sizeof(dns0x20name)) {
    status = ARES_EBADNAME;
    goto done;
  }

  memset(dns0x20name, 0, sizeof(dns0x20name));

  /* Fetch the minimum amount of random data we'd need for the string, which
   * is 1 bit per byte */
  total_bits     = ((len + 7) / 8) * 8;
  remaining_bits = total_bits;
  ares_rand_bytes(channel->rand_state, randdata, total_bits / 8);

  /* Randomly apply 0x20 to name */
  for (i = 0; i < len; i++) {
    size_t bit;

    /* Only apply 0x20 to alpha characters */
    if (!ares_isalpha(name[i])) {
      dns0x20name[i] = name[i];
      continue;
    }

    /* coin flip */
    bit = total_bits - remaining_bits;
    if (randdata[bit / 8] & (1 << (bit % 8))) {
      dns0x20name[i] = name[i] | 0x20;                          /* Set 0x20 */
    } else {
      dns0x20name[i] = (char)(((unsigned char)name[i]) & 0xDF); /* Unset 0x20 */
    }
    remaining_bits--;
  }

  status = ares_dns_record_query_set_name(dnsrec, 0, dns0x20name);

done:
  return status;
}

ares_status_t
  ares_send_direct_nolock(ares_channel_t *channel, ares_server_t *server,
                          ares_send_flags_t        flags,
                          const ares_dns_record_t *dnsrec, char *qcache_key,
                          ares_callback_dnsrec callback, void *arg,
                          unsigned short id, ares_query_group_t *group)
{
  ares_query_t  *query;
  ares_timeval_t now;
  ares_status_t  status;

  ares_tvnow(&now);

  /* Allocate space for query and allocated fields. */
  query = ares_malloc(sizeof(ares_query_t));
  if (!query) {
    /* LCOV_EXCL_START: OutOfMemory */
    ares_free(qcache_key);
    callback(arg, ARES_ENOMEM, 0, NULL);
    return ARES_ENOMEM;
    /* LCOV_EXCL_STOP */
  }
  memset(query, 0, sizeof(*query));

  query->channel      = channel;
  query->qid          = id;
  query->serial       = ++channel->query_serial;
  query->timeout.sec  = 0;
  query->timeout.usec = 0;
  query->using_tcp =
    (channel->flags & ARES_FLAG_USEVC) ? ARES_TRUE : ARES_FALSE;

  /* Duplicate Query */
  /* The query adopts the key derived above; ares_free_query() releases it. */
  query->qcache_key = qcache_key;
  qcache_key        = NULL;

  status = ares_dns_record_duplicate_ex(&query->query, dnsrec);
  if (status != ARES_SUCCESS) {
    /* Sometimes we might get a EBADRESP response from duplicate due to
     * the way it works (write and parse), rewrite it to EBADQUERY. */
    if (status == ARES_EBADRESP) {
      status = ARES_EBADQUERY;
    }
    /* ares_free_query() rather than ares_free(): the query was zeroed above,
     * so detaching finds every node NULL and the qid not yet registered, and
     * it also releases qcache_key.  Reachable without memory pressure -- a
     * name that is not a valid hostname fails the duplicate. */
    ares_free_query(query);
    callback(arg, status, 0, NULL);
    return status;
  }

  ares_dns_record_set_id(query->query, id);

  if (channel->flags & ARES_FLAG_DNS0x20 && !query->using_tcp) {
    status = ares_apply_dns0x20(channel, query->query);
    if (status != ARES_SUCCESS) {
      /* LCOV_EXCL_START: OutOfMemory */
      callback(arg, status, 0, NULL);
      ares_free_query(query);
      return status;
      /* LCOV_EXCL_STOP */
    }
  }

  /* Fill in query arguments. */
  query->callback = callback;
  query->arg      = arg;

  /* Initialize query status. */
  query->try_count = 0;

  if (flags & ARES_SEND_FLAG_NORETRY) {
    query->no_retries = ARES_TRUE;
  }

  query->error_status = ARES_SUCCESS;
  query->timeouts     = 0;

  /* Initialize our list nodes. */
  query->node_queries_by_timeout = NULL;
  query->node_queries_to_conn    = NULL;

  /* Chain the query into the list of all queries. */
  query->node_all_queries = ares_llist_insert_last(channel->all_queries, query);
  if (query->node_all_queries == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    callback(arg, ARES_ENOMEM, 0, NULL);
    ares_free_query(query);
    return ARES_ENOMEM;
    /* LCOV_EXCL_STOP */
  }

  /* Keep track of queries bucketed by qid, so we can process DNS
   * responses quickly.
   */
  if (!ares_htable_szvp_insert(channel->queries_by_qid, query->qid, query)) {
    /* LCOV_EXCL_START: OutOfMemory */
    /* The query is already chained into all_queries, so a reentrant
     * ares_cancel() from the callback below would find it, run the
     * application callback a second time for one lookup, and free it -- and
     * the ares_free_query() here would then double-free.  Same ordering as
     * ares_cancel() and ares_destroy(): unlink first, notify second. */
    ares_detach_query(query);
    callback(arg, ARES_ENOMEM, 0, NULL);
    ares_free_query(query);
    return ARES_ENOMEM;
    /* LCOV_EXCL_STOP */
  }

  query->queue_group = group;
  ares_query_queue_set_query(group, query);
  ares_query_queue_track_direct(query);

  /* Perform the first query action. */

  /* Sending opens and writes to connections and can mark a server down, both
   * of which notify.  This bracket keeps any connection or server unlinked
   * during the send readable until it returns.  It is never the outermost
   * one: every public entry point that can get here, and query processing,
   * holds its own, so delivery waits until the caller -- which may still be
   * holding its own lookup state, as ares_getaddrinfo() does -- has unwound
   * too. */
  ares_deferred_cb_enter(channel);
  status = ares_send_query(server, query, &now);
  ares_deferred_cb_leave(channel);

  return status;
}

ares_status_t ares_send_nolock_ex(ares_channel_t          *channel,
                                  ares_server_t           *server,
                                  ares_send_flags_t        flags,
                                  const ares_dns_record_t *dnsrec,
                                  ares_callback_dnsrec callback, void *arg,
                                  unsigned short *qid, size_t *handle)
{
  ares_timeval_t     now;
  ares_status_t      status;
  unsigned short     id;
  ares_dns_record_t *response   = NULL;
  char              *qcache_key = NULL;

  if (handle != NULL) {
    *handle = 0;
  }

  /* Keep queue admission behind the same destruction refusal used by the
   * legacy path. A retrying destruction callback must not recurse through
   * scheduler admission without bound. */
  if (!channel->sys_up) {
    if (!channel->in_shutdown_refusal) {
      channel->in_shutdown_refusal = ARES_TRUE;
      callback(arg, ARES_EDESTRUCTION, 0, NULL);
      channel->in_shutdown_refusal = ARES_FALSE;
    }
    return ARES_EDESTRUCTION;
  }

  if (ares_slist_len(channel->servers) == 0) {
    callback(arg, ARES_ENOSERVER, 0, NULL);
    return ARES_ENOSERVER;
  }

  ares_tvnow(&now);
  /* Calculate the cache key once from the caller's original request. The send
   * path can later mutate its private duplicate, such as while falling back
   * from EDNS, but cache insertion must retain the original lookup key. */
  if (channel->qcache_max_ttl > 0) {
    qcache_key = ares_qcache_calc_key(dnsrec);
    if (qcache_key == NULL) {
      callback(arg, ARES_ENOMEM, 0, NULL); /* LCOV_EXCL_LINE: OutOfMemory */
      return ARES_ENOMEM;                  /* LCOV_EXCL_LINE: OutOfMemory */
    }
  }
  if (qcache_key != NULL && !(flags & ARES_SEND_FLAG_NOCACHE)) {
    status = ares_qcache_fetch(channel, &now, qcache_key, &response);
    if (status != ARES_ENOTFOUND) {
      ares_free(qcache_key);
      callback(arg, status, 0, response);
      ares_dns_record_destroy(response);
      return status;
    }
  }
  if (channel->query_queue != NULL && server == NULL) {
    return ares_query_queue_admit(channel, flags, dnsrec, qcache_key, callback,
                                  arg, qid, handle);
  }

  /* Explicit-server recovery probes use one no-retry transaction outside the
   * user active limit so a saturated queue cannot prevent server recovery. */
  status = ares_query_queue_new_id(channel, &id);
  if (status != ARES_SUCCESS) {
    ares_free(qcache_key);
    callback(arg, status, 0, NULL);
    return status;
  }
  status = ares_send_direct_nolock(channel, server, flags, dnsrec, qcache_key,
                                   callback, arg, id, NULL);
  if (status == ARES_SUCCESS && qid != NULL) {
    *qid = id;
  }
  return status;
}

ares_status_t ares_send_nolock(ares_channel_t *channel, ares_server_t *server,
                               ares_send_flags_t        flags,
                               const ares_dns_record_t *dnsrec,
                               ares_callback_dnsrec callback, void *arg,
                               unsigned short *qid)
{
  return ares_send_nolock_ex(channel, server, flags, dnsrec, callback, arg, qid,
                             NULL);
}

ares_status_t ares_send_dnsrec(ares_channel_t          *channel,
                               const ares_dns_record_t *dnsrec,
                               ares_callback_dnsrec callback, void *arg,
                               unsigned short *qid)
{
  ares_status_t status;

  if (channel == NULL) {
    return ARES_EFORMERR; /* LCOV_EXCL_LINE: DefensiveCoding */
  }

  ares_channel_lock(channel);
  /* Notifications raised along the way are delivered once this whole call
   * has unwound, not from inside the internals it runs.  See
   * ares_deferred_cb_enter(). */
  ares_deferred_cb_enter(channel);

  status = ares_send_nolock(channel, NULL, 0, dnsrec, callback, arg, qid);

  ares_deferred_cb_leave(channel);
  ares_channel_unlock(channel);

  return status;
}

void ares_send(ares_channel_t *channel, const unsigned char *qbuf, int qlen,
               ares_callback callback, void *arg)
{
  ares_dns_record_t *dnsrec = NULL;
  ares_status_t      status;
  void              *carg = NULL;

  if (channel == NULL) {
    return;
  }

  /* Verify that the query is at least long enough to hold the header. */
  if (qlen < HFIXEDSZ || qlen >= (1 << 16)) {
    callback(arg, ARES_EBADQUERY, 0, NULL, 0);
    return;
  }

  status = ares_dns_parse(qbuf, (size_t)qlen, 0, &dnsrec);
  if (status != ARES_SUCCESS) {
    callback(arg, (int)status, 0, NULL, 0);
    return;
  }

  carg = ares_dnsrec_convert_arg(callback, arg);
  if (carg == NULL) {
    /* LCOV_EXCL_START: OutOfMemory */
    status = ARES_ENOMEM;
    ares_dns_record_destroy(dnsrec);
    callback(arg, (int)status, 0, NULL, 0);
    return;
    /* LCOV_EXCL_STOP */
  }

  ares_send_dnsrec(channel, dnsrec, ares_dnsrec_convert_cb, carg, NULL);

  ares_dns_record_destroy(dnsrec);
}

size_t ares_queue_active_queries(const ares_channel_t *channel)
{
  size_t len;

  if (channel == NULL) {
    return 0;
  }

  ares_channel_lock(channel);

  len = ares_query_queue_count(channel);

  ares_channel_unlock(channel);

  return len;
}
