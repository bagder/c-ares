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
 * Fuzzer for the c-ares channel initialization and option surfaces.
 *
 * Threat model: RES_OPTIONS / LOCALDOMAIN environment variables and the
 * ares_init_options()/ares_dup()/ares_save_options() option machinery are
 * untrusted-adjacent (multi-tenant environments export these variables;
 * applications construct options from their own configuration).  The
 * option setters/getters and the environment parsing hold dark lines not
 * reachable through the query fuzzers.
 *
 * Shape: option-matrix harness.  The fuzz input selects which fields of
 * struct ares_options to set (all values bounded), configures the
 * environment, initializes a channel (plain ares_init() or
 * ares_init_options()), then round-trips it through ares_save_options()/
 * ares_destroy_options() and ares_dup(), and exercises the local-address
 * setters.  No queries are issued.
 *
 * Input layout (sequential, missing bytes default to 0):
 *   [mode 1] bit0: use ares_init_options, bit1: set RES_OPTIONS,
 *            bit2: set LOCALDOMAIN, bit3: set local addresses
 *   [flags 1][timeoutms 2][tries 1][ndots 1][udp_port 2][tcp_port 2]
 *   [ednspsz 1][udp_max_queries 1][maxtimeout 2][qcache_ttl 2]
 *   [failover retry_chance 2][failover retry_delay 2]
 *   [ndomains 1]{[len 1][domain]}*
 *   [lookups len 1][lookups]
 *   [res_options len 1][bytes][localdomain len 1][bytes]
 *   [local ip4 4][local ip6 16][local dev len 1][name]
 */
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"

#define MAX_DOMAIN_LEN 63
#define MAX_ENV_LEN    200
#define MAX_DEV_LEN    15

typedef struct {
  const unsigned char *data;
  unsigned long        len;
  unsigned long        pos;
} fuzz_cursor_t;

static unsigned int take8(fuzz_cursor_t *c)
{
  if (c->pos >= c->len) {
    return 0;
  }
  return c->data[c->pos++];
}

static unsigned int take16(fuzz_cursor_t *c)
{
  unsigned int v  = (take8(c) << 8);
  v              |= take8(c);
  return v;
}

static unsigned int take32(fuzz_cursor_t *c)
{
  unsigned int v  = ((unsigned int)take16(c) << 16);
  v              |= take16(c);
  return v;
}

/* Consume a NUL-terminated bounded string. */
static void take_str(fuzz_cursor_t *c, char *buf, unsigned int maxlen)
{
  unsigned int n = take8(c);
  unsigned int i;

  if (n > maxlen) {
    n = maxlen;
  }
  if ((unsigned long)n > c->len - c->pos) {
    n = (unsigned int)(c->len - c->pos);
  }
  for (i = 0; i < n; i++) {
    buf[i] = (char)c->data[c->pos + i];
  }
  buf[n]  = 0;
  c->pos += n;
}

/* Minimal C90-compatible environment mutation (setenv/unsetenv are not
 * declared in strict C90 mode).  Replacements happen in the original
 * environ array; appends create a fresh array.  Everything is restored
 * after the run. */
extern char **environ;

static char  *g_env_strings[8]; /* our allocated NAME=VALUE entries */
static char **g_env_slots[8];   /* slots of replaced entries (orig array) */
static char  *g_env_old[8];     /* original values of replaced entries */
static char **g_env_fresh    = NULL; /* appended array, if any */
static char **g_orig_environ = NULL;
static size_t g_env_count;

static void fuzz_setenv(const char *name, const char *value)
{
  size_t nlen = strlen(name);
  size_t vlen = strlen(value);
  size_t i;
  char  *entry = malloc(nlen + vlen + 2);

  if (entry == NULL) {
    return;
  }
  if (g_env_count == 0) {
    g_orig_environ = environ;
  }
  memcpy(entry, name, nlen);
  entry[nlen] = '=';
  memcpy(entry + nlen + 1, value, vlen + 1);

  for (i = 0; environ[i] != NULL; i++) {
    if (strncmp(environ[i], name, nlen) == 0 && environ[i][nlen] == '=') {
      if (g_env_count < 8) {
        g_env_strings[g_env_count] = entry;
        g_env_slots[g_env_count]   = &environ[i];
        g_env_old[g_env_count]     = environ[i];
        g_env_count++;
        *g_env_slots[g_env_count - 1] = entry;
      } else {
        free(entry);
      }
      return;
    }
  }

  /* Name not present: append via a fresh array. */
  {
    size_t n     = i;
    char **fresh = malloc((n + 2) * sizeof(*fresh));
    if (fresh == NULL) {
      free(entry);
      return;
    }
    for (i = 0; i < n; i++) {
      fresh[i] = environ[i];
    }
    fresh[n]     = entry;
    fresh[n + 1] = NULL;
    if (g_env_count < 8) {
      g_env_strings[g_env_count] = entry;
      g_env_slots[g_env_count]   = NULL;
      g_env_old[g_env_count]     = NULL;
      g_env_count++;
      /* The superseded array (if any) is unreferenced after environ moves
       * to the new one; free it immediately to stay leak-free. */
      if (g_env_fresh != NULL) {
        free(g_env_fresh);
      }
      g_env_fresh = fresh;
      environ     = fresh;
    } else {
      free(fresh);
      free(entry);
    }
  }
}

static void fuzz_restoreenv(void)
{
  size_t i;

  if (g_env_count == 0) {
    return;
  }
  if (g_env_fresh != NULL) {
    environ = g_orig_environ;
  }
  for (i = 0; i < g_env_count; i++) {
    if (g_env_slots[i] != NULL) {
      *g_env_slots[i] = g_env_old[i];
    }
    free(g_env_strings[i]);
  }
  if (g_env_fresh != NULL) {
    free(g_env_fresh);
    g_env_fresh = NULL;
  }
  g_env_count = 0;
}

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  fuzz_cursor_t                       c;
  struct ares_options                 opts;
  struct ares_options                 saved;
  struct ares_server_failover_options failover;
  ares_channel_t                     *channel   = NULL;
  ares_channel_t                     *duped     = NULL;
  int                                 optmask   = 0;
  int                                 savedmask = 0;
  unsigned int                        mode;
  char                                resopt[MAX_ENV_LEN + 1];
  char                                localdomain[MAX_ENV_LEN + 1];
  static char                        *domains[4];
  static char                         domain0[MAX_DOMAIN_LEN + 1];
  static char                         domain1[MAX_DOMAIN_LEN + 1];
  static char                         domain2[MAX_DOMAIN_LEN + 1];
  static char                         domain3[MAX_DOMAIN_LEN + 1];
  static char                         lookups[5];
  static char                         devname[MAX_DEV_LEN + 1];
  unsigned char                       ip6[16];
  unsigned int                        i;

  memset(&c, 0, sizeof(c));
  c.data = data;
  c.len  = size;
  memset(&opts, 0, sizeof(opts));
  memset(&saved, 0, sizeof(saved));
  memset(&failover, 0, sizeof(failover));
  memset(resopt, 0, sizeof(resopt));
  memset(localdomain, 0, sizeof(localdomain));

  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  mode = take8(&c);

  if (mode & 0x02u) {
    take_str(&c, resopt, MAX_ENV_LEN);
    fuzz_setenv("RES_OPTIONS", resopt);
  }
  if (mode & 0x04u) {
    take_str(&c, localdomain, MAX_ENV_LEN);
    fuzz_setenv("LOCALDOMAIN", localdomain);
  }

  if (mode & 0x01u) {
    opts.flags                 = (int)take8(&c);
    optmask                   |= ARES_OPT_FLAGS;
    opts.timeout               = (int)(take16(&c) % 5000u) + 1;
    optmask                   |= ARES_OPT_TIMEOUTMS;
    opts.tries                 = (int)(take8(&c) % 8u) + 1;
    optmask                   |= ARES_OPT_TRIES;
    opts.ndots                 = (int)(take8(&c) % 16u);
    optmask                   |= ARES_OPT_NDOTS;
    opts.udp_port              = (unsigned short)take16(&c);
    optmask                   |= ARES_OPT_UDP_PORT;
    opts.tcp_port              = (unsigned short)take16(&c);
    optmask                   |= ARES_OPT_TCP_PORT;
    opts.ednspsz               = (int)(512u << (take8(&c) & 0x03u));
    optmask                   |= ARES_OPT_EDNSPSZ;
    opts.udp_max_queries       = (int)(take8(&c) % 100u) + 1;
    optmask                   |= ARES_OPT_UDP_MAX_QUERIES;
    opts.maxtimeout            = (int)(take16(&c) % 10000u) + 100;
    optmask                   |= ARES_OPT_MAXTIMEOUTMS;
    opts.qcache_max_ttl        = (unsigned int)(take16(&c) % 601u);
    optmask                   |= ARES_OPT_QUERY_CACHE;
    failover.retry_chance      = (unsigned short)take16(&c);
    failover.retry_delay       = (size_t)(take16(&c) % 1000u) + 1;
    opts.server_failover_opts  = failover;
    optmask                   |= ARES_OPT_SERVER_FAILOVER;

    opts.ndomains = (int)(take8(&c) % 4u);
    for (i = 0; i < 4; i++) {
      domains[i] = NULL;
    }
    for (i = 0; (int)i < opts.ndomains; i++) {
      switch (i) {
        case 0:
          take_str(&c, domain0, MAX_DOMAIN_LEN);
          domains[i] = domain0;
          break;
        case 1:
          take_str(&c, domain1, MAX_DOMAIN_LEN);
          domains[i] = domain1;
          break;
        case 2:
          take_str(&c, domain2, MAX_DOMAIN_LEN);
          domains[i] = domain2;
          break;
        default:
          take_str(&c, domain3, MAX_DOMAIN_LEN);
          domains[i] = domain3;
          break;
      }
    }
    opts.domains  = domains;
    optmask      |= ARES_OPT_DOMAINS;
    take_str(&c, lookups, 4);
    opts.lookups  = lookups;
    optmask      |= ARES_OPT_LOOKUPS;

    ares_init_options(&channel, &opts, optmask);
  } else {
    ares_init(&channel);
  }

  if (channel != NULL) {
    if (mode & 0x08u) {
      unsigned int raw = take32(&c);
      for (i = 0; i < sizeof(ip6); i++) {
        ip6[i] = (unsigned char)take8(&c);
      }
      take_str(&c, devname, MAX_DEV_LEN);
      ares_set_local_ip4(channel, raw);
      ares_set_local_ip6(channel, ip6);
      ares_set_local_dev(channel, devname);
    }

    if (ares_save_options(channel, &saved, &savedmask) == ARES_SUCCESS) {
      ares_destroy_options(&saved);
    }
    if (ares_dup(&duped, channel) == ARES_SUCCESS) {
      ares_destroy(duped);
      duped = NULL;
    }
  }

  if (duped != NULL) {
    ares_destroy(duped);
  }
  if (channel != NULL) {
    ares_destroy(channel);
  }
  fuzz_restoreenv();
  ares_library_cleanup();
  return 0;
}
