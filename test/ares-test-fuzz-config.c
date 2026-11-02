/* MIT License
 *
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
/*
 * Fuzzer for the c-ares configuration-file and files-lookup pipelines.
 *
 * Threat model: resolver configuration files are attacker-influenced in
 * real deployments (downloaded hosts lists, shared containers/images
 * shipping resolv.conf, multi-tenant systems) and c-ares config parsing
 * has a CVE history (2023).  The lookup name and service strings are the
 * classic untrusted input of server-side resolvers.  No existing fuzz
 * target feeds a resolv.conf, a hosts file, or files-only lookups.
 *
 * Shape: option-matrix + file-format harness.  The fuzz input carries a
 * full resolv.conf document, a full hosts-file document, a lookup node
 * name and a service string.  They are written to temporary files that
 * are wired in via ARES_OPT_RESOLVCONF / ARES_OPT_HOSTS_FILE, and a
 * channel with files-only lookups (deterministic, no network) then drives
 * ares_gethostbyname(), ares_getaddrinfo(), ares_gethostbyaddr() and
 * ares_getnameinfo() against that content.
 *
 * Input layout (length-prefixed sections):
 *   [resolvconf len 2][resolvconf bytes]
 *   [hosts len 2][hosts bytes]
 *   [node len 1][node bytes][service len 1][service bytes]
 *   [addr bytes 4][op byte]
 * op bits: 0-1 select the query family/mode, 2 requests gethostbyaddr on
 * the 4 address bytes, 3 requests getnameinfo with extra numeric flags.
 */
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ares.h"

#define MAX_RESOLVCONF_LEN 4096
#define MAX_HOSTS_LEN      8192
#define MAX_NODE_LEN       255
#define MAX_SERVICE_LEN    32

static int g_outstanding;

static void host_callback(void *arg, int status, int timeouts,
                          struct hostent *hostent)
{
  int i;

  (void)arg;
  (void)timeouts;
  g_outstanding--;
  if (status != ARES_SUCCESS || hostent == NULL) {
    return;
  }
  /* The hostent is owned and freed by c-ares after the callback returns. */
  (void)hostent->h_name;
  for (i = 0; hostent->h_aliases[i] != NULL; i++) {
    (void)hostent->h_aliases[i][0];
  }
  for (i = 0; hostent->h_addr_list[i] != NULL; i++) {
    (void)hostent->h_addr_list[i][0];
  }
}

static void addrinfo_callback(void *arg, int status, int timeouts,
                              struct ares_addrinfo *addrinfo)
{
  const struct ares_addrinfo_node *node;
  const struct ares_addrinfo_cname *cname;

  (void)arg;
  (void)timeouts;
  g_outstanding--;
  if (status != ARES_SUCCESS || addrinfo == NULL) {
    return;
  }
  for (node = addrinfo->nodes; node != NULL; node = node->ai_next) {
    (void)node->ai_family;
  }
  for (cname = addrinfo->cnames; cname != NULL; cname = cname->next) {
    (void)cname->alias;
    (void)cname->name;
  }
  ares_freeaddrinfo(addrinfo);
}

static void nameinfo_callback(void *arg, int status, int timeouts,
                              char *node, char *service)
{
  (void)arg;
  (void)timeouts;
  g_outstanding--;
  /* Numeric lookups hand back library-internal buffers; do not free. */
  if (status == ARES_SUCCESS) {
    (void)(node != NULL && node[0]);
    (void)(service != NULL && service[0]);
  }
}

/* Write data to a fresh temporary file; returns an allocated path or NULL.
 * Plain C90 constructs only (mkstemp/strdup are hidden in strict mode). */
static char *write_temp_file(const unsigned char *data, size_t len)
{
  char    path[64];
  char   *result;
  int     fd;
  long    off = 0;
  static unsigned long counter;

  counter++;
  sprintf(path, "/tmp/cares-fuzz-cfg-%d-%lu", (int)getpid(), counter);
  fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
  if (fd < 0) {
    return NULL;
  }
  while (len > 0 && (off = (long)write(fd, data + off, len)) > 0) {
    len -= (size_t)off;
    off  = 0;
  }
  close(fd);
  if (len > 0) {
    unlink(path);
    return NULL;
  }
  /* The caller unlinks the returned path after the channel is destroyed. */
  result = malloc(strlen(path) + 1);
  if (result != NULL) {
    strcpy(result, path);
  }
  return result;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  struct ares_options      opts;
  ares_channel_t          *channel = NULL;
  int                      optmask = 0;
  static char              lookups[] = "f";
  unsigned char            resolvbuf[MAX_RESOLVCONF_LEN];
  unsigned char            hostsbuf[MAX_HOSTS_LEN];
  char                     node[MAX_NODE_LEN + 1];
  char                     service[MAX_SERVICE_LEN + 1];
  char                    *resolvconf_path = NULL;
  char                    *hosts_path      = NULL;
  size_t                   resolvlen;
  size_t                   hostslen;
  size_t                   nodelen;
  size_t                   servicelen;
  unsigned long            pos = 0;
  unsigned int             addr = 0;
  unsigned int             op = 0;
  int                      round;

  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }
  g_outstanding = 0;

  /* Parse the length-prefixed sections. */
  if (size < 2) {
    goto done;
  }
  resolvlen = ((size_t)data[0] << 8) | (size_t)data[1];
  pos = 2;
  if (resolvlen > MAX_RESOLVCONF_LEN || pos + resolvlen > size) {
    goto done;
  }
  memcpy(resolvbuf, data + pos, resolvlen);
  pos += resolvlen;
  if (pos + 2 > size) {
    goto done;
  }
  hostslen = ((size_t)data[pos] << 8) | (size_t)data[pos + 1];
  pos += 2;
  if (hostslen > MAX_HOSTS_LEN || pos + hostslen > size) {
    goto done;
  }
  memcpy(hostsbuf, data + pos, hostslen);
  pos += hostslen;
  if (pos + 1 > size) {
    goto done;
  }
  nodelen = data[pos++];
  if (nodelen > MAX_NODE_LEN || pos + nodelen + 1 > size) {
    goto done;
  }
  memcpy(node, data + pos, nodelen);
  node[nodelen] = 0;
  pos += nodelen;
  servicelen = data[pos++];
  if (servicelen > MAX_SERVICE_LEN || pos + servicelen + 5 > size) {
    goto done;
  }
  memcpy(service, data + pos, servicelen);
  service[servicelen] = 0;
  pos += servicelen;
  memcpy(&addr, data + pos, 4);
  pos += 4;
  op = data[pos];

  resolvconf_path = write_temp_file(resolvbuf, resolvlen);
  hosts_path      = write_temp_file(hostsbuf, hostslen);
  if (resolvconf_path == NULL || hosts_path == NULL) {
    goto done;
  }

  memset(&opts, 0, sizeof(opts));
  opts.timeout       = 500; /* milliseconds via ARES_OPT_TIMEOUTMS */
  optmask           |= ARES_OPT_TIMEOUTMS;
  opts.tries         = 1;
  optmask           |= ARES_OPT_TRIES;
  opts.lookups       = lookups; /* files only: deterministic, offline */
  optmask           |= ARES_OPT_LOOKUPS;
  opts.ednspsz       = 1232;
  optmask           |= ARES_OPT_EDNSPSZ;
  opts.resolvconf_path = resolvconf_path;
  optmask           |= ARES_OPT_RESOLVCONF;
  opts.hosts_path      = hosts_path;
  optmask           |= ARES_OPT_HOSTS_FILE;

  if (ares_init_options(&channel, &opts, optmask) != ARES_SUCCESS) {
    goto done;
  }

  /* Drive the files-based lookup pipelines. */
  switch (op & 0x03u) {
    case 0:
      g_outstanding++;
      ares_gethostbyname(channel, node, AF_INET, host_callback, NULL);
      break;
    case 1:
      g_outstanding++;
      ares_gethostbyname(channel, node, AF_INET6, host_callback, NULL);
      break;
    default: {
      struct ares_addrinfo_hints hints;
      memset(&hints, 0, sizeof(hints));
      hints.ai_family   = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      g_outstanding++;
      ares_getaddrinfo(channel, node,
                       (op & 0x10u) ? service : NULL, &hints,
                       addrinfo_callback, NULL);
      break;
    }
  }

  if (op & 0x04u) {
    struct in_addr in;
    memcpy(&in, &addr, sizeof(in));
    g_outstanding++;
    ares_gethostbyaddr(channel, &in, sizeof(in), AF_INET, host_callback, NULL);
  }

  if (op & 0x08u) {
    struct sockaddr_in  sa4;
    struct sockaddr_in6 sa6;
    struct sockaddr    *sa;
    socklen_t           salen;
    int                 niflags = ARES_NI_NUMERICHOST | ARES_NI_LOOKUPHOST |
                                  ARES_NI_LOOKUPSERVICE;
    if (op & 0x10u) {
      niflags |= ARES_NI_DGRAM;
    }
    if (op & 0x20u) {
      niflags |= ARES_NI_NOFQDN;
    }
    if ((op & 0x40u) && !(op & 0x80u)) {
      niflags |= ARES_NI_NUMERICSERV;
    }
    memset(&sa4, 0, sizeof(sa4));
    sa4.sin_family = AF_INET;
    sa4.sin_addr   = *((struct in_addr *)&addr);
    sa4.sin_port   = htons((unsigned short)((addr >> 16) | 1));
    memset(&sa6, 0, sizeof(sa6));
    sa6.sin6_family = AF_INET6;
    sa6.sin6_port   = htons((unsigned short)((addr >> 16) | 1));
    sa6.sin6_addr.s6_addr[15] = 1;
    if (op & 0x80u) {
      sa    = (struct sockaddr *)&sa6;
      salen = sizeof(sa6);
    } else {
      sa    = (struct sockaddr *)&sa4;
      salen = sizeof(sa4);
    }
    g_outstanding++;
    ares_getnameinfo(channel, sa, salen, niflags, nameinfo_callback, NULL);
  }

  /* Files-based lookups complete inline; pump the channel bounded in case
   * a lookup deferred its completion. */
  for (round = 0; round < 8 && g_outstanding > 0; round++) {
    ares_process_fd(channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
  }

  ares_destroy(channel);
  channel = NULL;

done:
  if (channel != NULL) {
    ares_destroy(channel);
  }
  if (resolvconf_path != NULL) {
    unlink(resolvconf_path);
    free(resolvconf_path);
  }
  if (hosts_path != NULL) {
    unlink(hosts_path);
    free(hosts_path);
  }
  ares_library_cleanup();
  return 0;
}
