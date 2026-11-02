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
 * Fuzzer for the c-ares response processing state machine.
 *
 * Threat model: the canonical attacker of a resolver library is the DNS
 * server itself (a malicious or spoofing server, or any middlebox) which
 * controls every byte of the response, as well as the transport behaviour
 * (truncation, zero-length datagrams, TCP fallback).  No existing fuzz
 * target drives a server response through a live query: this harness does.
 *
 * Shape: stateful sequence.  A real loopback UDP/TCP server pair is bound
 * to 127.0.0.1 (ephemeral port) and configured as the only nameserver of a
 * channel with a fixed, representative configuration (EDNS enabled, one
 * search domain, query cache enabled).  The fuzzer controls the response
 * bytes only: the query ID and question section are mirrored from the
 * genuine query the library itself emitted, exactly like a real on-path
 * server would do, and everything else (flags, counts, all records) comes
 * from the fuzz input.
 *
 * Input format (little structure, maximum attacker entropy):
 *   [op byte]
 *   [flags 2 bytes][ancount 2][nscount 2][arcount 2]
 *   [response record payload ...]
 * Missing bytes default to a typical NOERROR header with no records; an
 * input with less than 2 bytes produces a zero-length response datagram.
 *
 * The op byte controls which resolving API is driven (gethostbyname A/AAAA,
 * ares_getaddrinfo, ares_gethostbyaddr), whether a search-domain short name
 * is used, and whether the query is repeated to exercise the query cache.
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "ares.h"

#define MAX_RESPONSE_LEN 65535
#define MAX_PAYLOAD_LEN  8192
#define MAX_ROUNDS       4

/* op byte bits */
#define OP_QUERY_MASK 0x03u /* 0=gethostbyname A, 1=gethostbyname AAAA, \
                             * 2=getaddrinfo,   3=gethostbyaddr PTR    */
#define OP_SHORTNAME  0x04u /* use search-domain short name */
#define OP_REPEAT     0x08u /* re-issue query to exercise qcache */

typedef struct {
  ares_channel_t *channel;
  int             udp_sock;
  int             tcp_sock;
  int             in_port;
} ares_fuzz_state_t;

static ares_fuzz_state_t st;
static int               g_outstanding;

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
  /* Touch the delivered result so downstream corruption is observable.
   * NOTE: the hostent is owned by c-ares and is freed by the library after
   * the callback returns (see end_hquery()/end_aquery()); the callback must
   * not free it. */
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

  (void)arg;
  (void)timeouts;
  g_outstanding--;
  if (status != ARES_SUCCESS || addrinfo == NULL) {
    return;
  }
  for (node = addrinfo->nodes; node != NULL; node = node->ai_next) {
    (void)node->ai_family;
  }
  ares_freeaddrinfo(addrinfo);
}

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

static int set_nonblocking(int fd)
{
  int flags;

  flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return -1;
  }
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/* Bind a loopback server of the given type on the requested port
 * (0 = ephemeral); returns 0 on success. */
static int bind_loopback(int type, int protocol, int port_req, int *out_sock,
                         int *out_port)
{
  struct sockaddr_in sa;
  socklen_t          salen;
  int                sfd;
  int                rv;

  sfd = socket(AF_INET, type, protocol);
  if (sfd < 0) {
    return -1;
  }
  if (type == SOCK_STREAM) {
    int one = 1;
    rv = setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (rv != 0) {
      close(sfd);
      return -1;
    }
  }
  memset(&sa, 0, sizeof(sa));
  sa.sin_family      = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port        = htons((unsigned short)port_req);
  if (bind(sfd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
    close(sfd);
    return -1;
  }
  if (type == SOCK_STREAM && listen(sfd, 4) != 0) {
    close(sfd);
    return -1;
  }
  if (set_nonblocking(sfd) != 0) {
    close(sfd);
    return -1;
  }
  salen = sizeof(sa);
  if (getsockname(sfd, (struct sockaddr *)&sa, &salen) != 0) {
    close(sfd);
    return -1;
  }
  *out_sock = sfd;
  *out_port = (int)ntohs(sa.sin_port);
  return 0;
}

/* Fixed, representative channel configuration: the attacker controls the
 * response bytes, not the configuration.  EDNS + cache + one search domain
 * so the response paths (OPT/cookie, cache, search rewrites) are live. */
static ares_channel_t *create_channel(void)
{
  struct ares_options        opts;
  struct ares_addr_port_node server;
  ares_channel_t            *channel = NULL;
  int                        optmask = 0;
  static char               *domains[1];
  static char                domain0[] = "example.com";
  static char                lookups[] = "b";

  memset(&opts, 0, sizeof(opts));
  opts.flags         = ARES_FLAG_EDNS;
  optmask           |= ARES_OPT_FLAGS;
  opts.timeout       = 1000; /* milliseconds via ARES_OPT_TIMEOUTMS */
  optmask           |= ARES_OPT_TIMEOUTMS;
  opts.tries         = 2;
  optmask           |= ARES_OPT_TRIES;
  opts.ndots         = 1;
  optmask           |= ARES_OPT_NDOTS;
  domains[0]         = domain0;
  opts.domains       = domains;
  opts.ndomains      = 1;
  optmask           |= ARES_OPT_DOMAINS;
  opts.lookups       = lookups;
  optmask           |= ARES_OPT_LOOKUPS;
  opts.ednspsz       = 1232;
  optmask           |= ARES_OPT_EDNSPSZ;
  opts.qcache_max_ttl = 300;
  optmask           |= ARES_OPT_QUERY_CACHE;

  if (ares_init_options(&channel, &opts, optmask) != ARES_SUCCESS) {
    return NULL;
  }

  memset(&server, 0, sizeof(server));
  server.family           = AF_INET;
  server.addr.addr4.s_addr = htonl(INADDR_LOOPBACK);
  server.udp_port         = st.in_port;
  server.tcp_port         = st.in_port;
  if (ares_set_servers_ports(channel, &server) != ARES_SUCCESS) {
    ares_destroy(channel);
    return NULL;
  }
  return channel;
}

static void issue_query(unsigned int op)
{
  static const char     fqdn[]   = "www.example.com";
  static const char     shortnm[] = "mail";
  const char           *name;
  struct ares_addrinfo_hints hints;

  name = (op & OP_SHORTNAME) ? shortnm : fqdn;

  switch (op & OP_QUERY_MASK) {
    case 0:
      g_outstanding++;
      ares_gethostbyname(st.channel, name, AF_INET, host_callback, NULL);
      break;
    case 1:
      g_outstanding++;
      ares_gethostbyname(st.channel, name, AF_INET6, host_callback, NULL);
      break;
    case 2:
      memset(&hints, 0, sizeof(hints));
      hints.ai_family   = AF_UNSPEC;
      hints.ai_socktype = SOCK_STREAM;
      g_outstanding++;
      ares_getaddrinfo(st.channel, name, NULL, &hints, addrinfo_callback,
                       NULL);
      break;
    default: {
      struct in_addr addr;
      addr.s_addr = htonl(0x0a141e28u); /* 10.20.30.40 */
      g_outstanding++;
      ares_gethostbyaddr(st.channel, &addr, sizeof(addr), AF_INET,
                         host_callback, NULL);
      break;
    }
  }
}

/* Extract the question section end offset of a received query packet.
 * Returns the offset just past the question, or 0 if malformed. */
static size_t query_question_end(const unsigned char *query, size_t qlen)
{
  size_t i;

  if (qlen < 12) {
    return 0;
  }
  i = 12;
  while (i < qlen) {
    unsigned int len = query[i];
    if (len == 0) {
      i++;
      if (i + 4 > qlen) {
        return 0;
      }
      return i + 4;
    }
    if (len & 0xC0u) {
      return 0; /* no compression expected in our own query */
    }
    i += (size_t)len + 1;
    if (i > qlen) {
      return 0;
    }
  }
  return 0;
}

static int read_exact(int fd, unsigned char *buf, size_t len, int tries)
{
  size_t got = 0;
  int    t;

  for (t = 0; t < tries && got < len; t++) {
    struct pollfd pfd;
    ssize_t       rv;
    pfd.fd      = fd;
    pfd.events  = POLLIN;
    pfd.revents = 0;
    if (poll(&pfd, 1, 2) <= 0) {
      continue;
    }
    rv = recv(fd, buf + got, len - got, 0);
    if (rv <= 0) {
      if (rv == 0) {
        return -1;
      }
      continue;
    }
    got += (size_t)rv;
  }
  return (got == len) ? 0 : -1;
}

/* Mirror ID + question from the genuine query and deliver the response.
 * resp layout: [flags 2][ancount 2][nscount 2][arcount 2][records...] with
 * qdcount always 1 (the mirrored question). */
static void tcp_respond(int fd, const unsigned char *query, size_t qlen,
                        const unsigned char *resp, size_t rlen)
{
  unsigned char out[MAX_RESPONSE_LEN + 2];
  size_t        qend;
  size_t        total;

  if (rlen < 8) {
    return;
  }
  qend  = query_question_end(query, qlen);
  if (qend == 0) {
    return;
  }
  total = 12 + (qend - 12) + (rlen - 8);
  if (total + 2 > sizeof(out)) {
    return;
  }
  out[0] = (unsigned char)(total >> 8);
  out[1] = (unsigned char)(total & 0xFF);
  out[2] = query[0];
  out[3] = query[1];
  memcpy(out + 4, resp, 2);         /* flags */
  out[4 + 2] = 0;                   /* qdcount = 1 */
  out[4 + 3] = 1;
  memcpy(out + 8, resp + 2, 6);     /* an/ns/ar counts */
  memcpy(out + 12, query + 12, qend - 12);
  memcpy(out + 12 + (qend - 12), resp + 8, rlen - 8);
  if (send(fd, out, total + 2, MSG_DONTWAIT) < 0) {
    return;
  }
}

static void udp_respond(const unsigned char *query, size_t qlen,
                        const struct sockaddr *sa, socklen_t salen,
                        const unsigned char *resp, size_t rlen)
{
  unsigned char out[MAX_RESPONSE_LEN];
  size_t        qend;
  size_t        total;

  if (rlen < 8) {
    /* Zero-length (or truncated) response datagram: regression shape for
     * the historical 0-byte UDP payload crash. */
    sendto(st.udp_sock, out, 0, MSG_DONTWAIT, sa, salen);
    return;
  }
  qend = query_question_end(query, qlen);
  if (qend == 0) {
    return;
  }
  total = 12 + (qend - 12) + (rlen - 8);
  if (total > sizeof(out)) {
    return;
  }
  out[0] = query[0];
  out[1] = query[1];
  memcpy(out + 2, resp, 2);         /* flags */
  out[4] = 0;                       /* qdcount = 1 */
  out[5] = 1;
  memcpy(out + 6, resp + 2, 6);     /* an/ns/ar counts */
  memcpy(out + 12, query + 12, qend - 12);
  memcpy(out + 12 + (qend - 12), resp + 8, rlen - 8);
  sendto(st.udp_sock, out, total, MSG_DONTWAIT, sa, salen);
}

/* One server-side round: drain pending queries and answer them. */
static void inject_round(const unsigned char *resp, size_t rlen)
{
  struct pollfd         pfd[2];
  unsigned char         query[2 * MAX_RESPONSE_LEN];
  struct sockaddr_in    sa;
  socklen_t             salen;
  ssize_t               n;

  pfd[0].fd      = st.udp_sock;
  pfd[0].events  = POLLIN;
  pfd[0].revents = 0;
  pfd[1].fd      = st.tcp_sock;
  pfd[1].events  = POLLIN;
  pfd[1].revents = 0;
  poll(pfd, 2, 0);

  if (pfd[0].revents & POLLIN) {
    salen = sizeof(sa);
    n = recvfrom(st.udp_sock, query, sizeof(query), 0,
                 (struct sockaddr *)&sa, &salen);
    if (n >= 12) {
      udp_respond(query, (size_t)n, (struct sockaddr *)&sa, salen, resp, rlen);
    }
  }

  if (pfd[1].revents & POLLIN) {
    int cfd = accept(st.tcp_sock, NULL, NULL);
    if (cfd >= 0) {
      set_nonblocking(cfd);
      if (read_exact(cfd, query, 2, 3) == 0) {
        size_t tlen =
          ((size_t)query[0] << 8) | (size_t)query[1];
        if (tlen <= sizeof(query) &&
            read_exact(cfd, query, tlen, 3) == 0 && tlen >= 12) {
          tcp_respond(cfd, query, tlen, resp, rlen);
        }
      }
      close(cfd);
    }
  }
}

static void process_channel(void)
{
  ares_socket_t socks[ARES_GETSOCK_MAXNUM];
  int           bits;
  int           i;

  /* ares_getsock() returns a bitmask of readable/writable sockets, not a
   * socket count.  The upstream convenience macros shift into the sign bit
   * at i == 15 (UB); use unsigned shifts with identical semantics. */
  bits = ares_getsock(st.channel, socks, (int)ARES_GETSOCK_MAXNUM);
  for (i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
    if (((unsigned int)bits & (1u << i)) != 0u ||
        ((unsigned int)bits & (1u << (i + 16))) != 0u) {
      ares_process_fd(st.channel, socks[i], ARES_SOCKET_BAD);
    }
  }
}

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  static const unsigned char dflt[8] = { 0x81, 0x80, 0, 0, 0, 0, 0, 0 };
  unsigned char resp[MAX_PAYLOAD_LEN + 9];
  size_t        rlen = 0;
  size_t        plen;
  size_t        k;
  unsigned int  op = 0;
  int           round_count;

  memset(&st, 0, sizeof(st));
  st.udp_sock = -1;
  st.tcp_sock = -1;
  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  if (size >= 1) {
    op = data[0];
  }
  if (size >= 2) {
    /* [op][flags 2][ancount 2][nscount 2][arcount 2][records...] with
     * missing header bytes defaulted; everything after byte 9 is the
     * attacker's record data. */
    for (k = 0; k < 8; k++) {
      resp[rlen++] = (size >= k + 2) ? data[k + 1] : dflt[k];
    }
    plen = (size > 9) ? (size - 9) : 0;
    if (plen > MAX_PAYLOAD_LEN) {
      plen = MAX_PAYLOAD_LEN;
    }
    if (plen > 0) {
      memcpy(resp + rlen, data + 9, plen);
    }
    rlen += plen;
  }
  /* size < 2 leaves rlen == 0: a zero-length response datagram is sent. */

  if (bind_loopback(SOCK_DGRAM, IPPROTO_UDP, 0, &st.udp_sock,
                    &st.in_port) != 0 ||
      bind_loopback(SOCK_STREAM, IPPROTO_TCP, st.in_port, &st.tcp_sock,
                    &st.in_port) != 0) {
    goto cleanup_no_channel;
  }

  st.channel = create_channel();
  if (st.channel == NULL) {
    goto cleanup_no_channel;
  }

  issue_query(op);

  /* Answer, process, repeat: covers truncation/TCP fallback, CNAME chases
   * (each round answers the freshly sent query with the same fuzzed
   * response), and multi-packet flows. */
  for (round_count = 0;
       round_count < MAX_ROUNDS && g_outstanding > 0;
       round_count++) {
    inject_round(resp, rlen);
    process_channel();
  }

  if (op & OP_REPEAT) {
    issue_query(op); /* likely served from the query cache */
    process_channel();
  }

  ares_destroy(st.channel);
  st.channel = NULL;

cleanup_no_channel:
  if (st.channel != NULL) {
    ares_destroy(st.channel);
  }
  if (st.udp_sock >= 0) {
    close(st.udp_sock);
  }
  if (st.tcp_sock >= 0) {
    close(st.tcp_sock);
  }
  ares_library_cleanup();
  return 0;
}
