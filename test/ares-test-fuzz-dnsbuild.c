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
 * Fuzzer for the c-ares DNS record construction and writing API.
 *
 * Threat model: c-ares writes DNS messages (queries carrying application
 * controlled names, OPT/EDNS options incl. server cookies, SVCB/HTTPS and
 * other modern RR types) and parses responses.  The existing parse fuzzer
 * only reaches the record *creation* and *setter* APIs indirectly; those
 * paths (ares_dns_record_create/query_add/rr_add, all typed setters, the
 * option array and the writer) hold the remaining dark lines of the record
 * module.
 *
 * Shape: component-API harness.  The fuzz input drives
 * ares_dns_record_create(), queries and RRs in all three sections with all
 * supported keys/datatypes (strings, ints, addresses, binary, ABINP arrays,
 * OPT options), then ares_dns_write(), then a re-parse of the written
 * message with full getter/tostr traversal of the parsed copy.
 *
 * Input layout (consumed sequentially, missing bytes default to 0):
 *   [id 2][flags 2][opcode 1][rcode 1]
 *   [nqueries 1]{ [namelen 1][name][type 1][class 1] }*
 *   for each of ANSWER/AUTHORITY/ADDITIONAL:
 *     [nrr 1]{ [namelen 1][name][type 1][class 1][ttl 4]
 *              [setmask 1][key values...] }*
 * Where key values are consumed per datatype of each key of the RR type.
 */
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ares.h"
#include "ares_dns_record.h"
#include "include/ares_mem.h"

#define MAX_NAME 255
#define MAX_BLOB 512
#define MAX_STR  128

static ares_dns_rec_type_t valid_types[] = {
  ARES_REC_TYPE_A,     ARES_REC_TYPE_NS,         ARES_REC_TYPE_CNAME,
  ARES_REC_TYPE_SOA,   ARES_REC_TYPE_PTR,        ARES_REC_TYPE_HINFO,
  ARES_REC_TYPE_MX,    ARES_REC_TYPE_TXT,        ARES_REC_TYPE_SIG,
  ARES_REC_TYPE_AAAA,  ARES_REC_TYPE_SRV,        ARES_REC_TYPE_NAPTR,
  ARES_REC_TYPE_OPT,   ARES_REC_TYPE_DS,         ARES_REC_TYPE_SSHFP,
  ARES_REC_TYPE_RRSIG, ARES_REC_TYPE_NSEC,       ARES_REC_TYPE_DNSKEY,
  ARES_REC_TYPE_NSEC3, ARES_REC_TYPE_NSEC3PARAM, ARES_REC_TYPE_TLSA,
  ARES_REC_TYPE_SVCB,  ARES_REC_TYPE_HTTPS,      ARES_REC_TYPE_URI,
  ARES_REC_TYPE_CAA
};
#define NUM_TYPES (sizeof(valid_types) / sizeof(valid_types[0]))

static ares_dns_class_t valid_classes[] = { ARES_CLASS_IN, ARES_CLASS_CHAOS,
                                            ARES_CLASS_HESIOD, ARES_CLASS_NONE,
                                            ARES_CLASS_ANY };
#define NUM_CLASSES (sizeof(valid_classes) / sizeof(valid_classes[0]))

static ares_dns_opcode_t valid_opcodes[] = {
  ARES_OPCODE_QUERY, ARES_OPCODE_IQUERY, ARES_OPCODE_STATUS, ARES_OPCODE_NOTIFY,
  ARES_OPCODE_UPDATE
};
#define NUM_OPCODES (sizeof(valid_opcodes) / sizeof(valid_opcodes[0]))

typedef struct {
  const unsigned char *data;
  size_t               len;
  size_t               pos;
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

static size_t take_blob(fuzz_cursor_t *c, unsigned char *buf, size_t maxlen);
static void set_rr_keys(fuzz_cursor_t *c, ares_dns_rr_t *rr,
                        ares_dns_rec_type_t rtype);

/* Exercise every getter/tostr on the re-parsed copy of the written
 * message so parse/write asymmetries surface. */
static void exercise_parsed(ares_dns_record_t *rec)
{
  size_t s;
  size_t i;

  (void)ares_dns_opcode_tostr(ares_dns_record_get_opcode(rec));
  (void)ares_dns_rcode_tostr(ares_dns_record_get_rcode(rec));
  (void)ares_dns_rec_type_tostr(ARES_REC_TYPE_SVCB);

  for (i = 0; i < ares_dns_record_query_cnt(rec); i++) {
    const char         *name = NULL;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;
    if (ares_dns_record_query_get(rec, i, &name, &qtype, &qclass) ==
        ARES_SUCCESS) {
      (void)ares_dns_rec_type_tostr(qtype);
      (void)ares_dns_class_tostr(qclass);
    }
  }

  for (s = ARES_SECTION_ANSWER; s <= ARES_SECTION_ADDITIONAL; s++) {
    size_t cnt = ares_dns_record_rr_cnt(rec, (ares_dns_section_t)s);
    for (i = 0; i < cnt; i++) {
      const ares_dns_rr_t *rr =
        ares_dns_record_rr_get(rec, (ares_dns_section_t)s, i);
      const ares_dns_rr_key_t *keys     = NULL;
      size_t                   keys_cnt = 0;
      size_t                   k;
      if (rr == NULL) {
        continue;
      }
      (void)ares_dns_rr_get_name(rr);
      (void)ares_dns_rec_type_tostr(ares_dns_rr_get_type(rr));
      (void)ares_dns_class_tostr(ares_dns_rr_get_class(rr));
      (void)ares_dns_rr_get_ttl(rr);
      keys = ares_dns_rr_get_keys(ares_dns_rr_get_type(rr), &keys_cnt);
      for (k = 0; keys != NULL && k < keys_cnt; k++) {
        switch (ares_dns_rr_key_datatype(keys[k])) {
          case ARES_DATATYPE_INADDR:
            (void)ares_dns_rr_get_addr(rr, keys[k]);
            break;
          case ARES_DATATYPE_INADDR6:
            (void)ares_dns_rr_get_addr6(rr, keys[k]);
            break;
          case ARES_DATATYPE_U8:
            (void)ares_dns_rr_get_u8(rr, keys[k]);
            break;
          case ARES_DATATYPE_U16:
            (void)ares_dns_rr_get_u16(rr, keys[k]);
            break;
          case ARES_DATATYPE_U32:
            (void)ares_dns_rr_get_u32(rr, keys[k]);
            break;
          case ARES_DATATYPE_NAME:
          case ARES_DATATYPE_STR:
            (void)ares_dns_rr_get_str(rr, keys[k]);
            break;
          case ARES_DATATYPE_BIN:
          case ARES_DATATYPE_BINP:
            {
              size_t blen = 0;
              (void)ares_dns_rr_get_bin(rr, keys[k], &blen);
              break;
            }
          case ARES_DATATYPE_ABINP:
            {
              size_t acnt = ares_dns_rr_get_abin_cnt(rr, keys[k]);
              size_t a;
              for (a = 0; a < acnt; a++) {
                size_t alen = 0;
                (void)ares_dns_rr_get_abin(rr, keys[k], a, &alen);
              }
              break;
            }
          case ARES_DATATYPE_OPT:
            {
              size_t               ocnt = ares_dns_rr_get_opt_cnt(rr, keys[k]);
              size_t               o;
              const unsigned char *oval = NULL;
              size_t               olen = 0;
              for (o = 0; o < ocnt; o++) {
                (void)ares_dns_rr_get_opt(rr, keys[k], o, &oval, &olen);
              }
              (void)ares_dns_rr_get_opt_byid(rr, keys[k], 10, &oval, &olen);
              break;
            }
          default:
            break;
        }
      }
    }
  }
}

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size);

int LLVMFuzzerTestOneInput(const unsigned char *data, unsigned long size)
{
  fuzz_cursor_t      c;
  ares_dns_record_t *rec    = NULL;
  unsigned char     *msg    = NULL;
  size_t             msglen = 0;
  ares_dns_record_t *rec2   = NULL;
  ares_dns_opcode_t  opcode;
  ares_dns_rcode_t   rcode;
  unsigned int       nq;
  unsigned int       sect;
  unsigned int       q;

  if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
    return 0;
  }

  memset(&c, 0, sizeof(c));
  c.data = data;
  c.len  = size;

  opcode = valid_opcodes[take8(&c) % NUM_OPCODES];
  rcode  = (ares_dns_rcode_t)(take8(&c) % 12u);

  if (ares_dns_record_create(&rec, (unsigned short)take16(&c),
                             (unsigned short)take16(&c), opcode,
                             rcode) != ARES_SUCCESS) {
    goto done;
  }

  nq = take8(&c) % 4u + 1u;
  for (q = 0; q < nq; q++) {
    unsigned char       name[MAX_NAME + 1];
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;
    take_blob(&c, name, MAX_NAME);
    qtype  = valid_types[take8(&c) % NUM_TYPES];
    qclass = valid_classes[take8(&c) % NUM_CLASSES];
    if (ares_dns_record_query_add(rec, (const char *)name, qtype, qclass) !=
        ARES_SUCCESS) {
      goto done;
    }
  }

  for (sect = ARES_SECTION_ANSWER; sect <= ARES_SECTION_ADDITIONAL; sect++) {
    unsigned int nrr = take8(&c) % 4u;
    unsigned int r;
    for (r = 0; r < nrr; r++) {
      unsigned char       name[MAX_NAME + 1];
      ares_dns_rr_t      *rr    = NULL;
      ares_dns_rec_type_t rtype = valid_types[take8(&c) % NUM_TYPES];
      take_blob(&c, name, MAX_NAME);
      if (ares_dns_record_rr_add(&rr, rec, (ares_dns_section_t)sect,
                                 (const char *)name, rtype,
                                 valid_classes[take8(&c) % NUM_CLASSES],
                                 take32(&c)) != ARES_SUCCESS) {
        continue;
      }
      set_rr_keys(&c, rr, rtype);
    }
  }

  if (ares_dns_write(rec, &msg, &msglen) == ARES_SUCCESS) {
    if (ares_dns_parse(msg, msglen, 0, &rec2) == ARES_SUCCESS) {
      exercise_parsed(rec2);
      ares_dns_record_destroy(rec2);
      rec2 = NULL;
    }
  }

done:
  ares_dns_record_destroy(rec2);
  ares_dns_record_destroy(rec);
  ares_free(msg);
  ares_library_cleanup();
  return 0;
}

/* Consume up to maxlen bytes into buf (NUL terminated), returns length. */
static size_t take_blob(fuzz_cursor_t *c, unsigned char *buf, size_t maxlen)
{
  size_t n = take8(c);

  if (n > maxlen) {
    n = maxlen;
  }
  if (n > c->len - c->pos) {
    n = c->len - c->pos;
  }
  memcpy(buf, c->data + c->pos, n);
  c->pos += n;
  buf[n]  = 0;
  return n;
}

/* Set every key of the RR from fuzz data, covering all datatypes. */
static void set_rr_keys(fuzz_cursor_t *c, ares_dns_rr_t *rr,
                        ares_dns_rec_type_t rtype)
{
  const ares_dns_rr_key_t *keys     = NULL;
  size_t                   keys_cnt = 0;
  size_t                   i;
  unsigned char            blob[MAX_BLOB + 1];
  size_t                   bloblen;

  keys = ares_dns_rr_get_keys(rtype, &keys_cnt);
  if (keys == NULL) {
    return;
  }

  for (i = 0; i < keys_cnt; i++) {
    switch (ares_dns_rr_key_datatype(keys[i])) {
      case ARES_DATATYPE_INADDR:
        {
          struct in_addr addr;
          unsigned int   raw = take32(c);
          memcpy(&addr, &raw, sizeof(addr));
          ares_dns_rr_set_addr(rr, keys[i], &addr);
          break;
        }
      case ARES_DATATYPE_INADDR6:
        {
          struct ares_in6_addr addr6;
          unsigned char        b6[16];
          size_t               j;
          for (j = 0; j < sizeof(b6); j++) {
            b6[j] = (unsigned char)take8(c);
          }
          memcpy(&addr6, b6, sizeof(addr6));
          ares_dns_rr_set_addr6(rr, keys[i], &addr6);
          break;
        }
      case ARES_DATATYPE_U8:
        ares_dns_rr_set_u8(rr, keys[i], (unsigned char)take8(c));
        break;
      case ARES_DATATYPE_U16:
        ares_dns_rr_set_u16(rr, keys[i], (unsigned short)take16(c));
        break;
      case ARES_DATATYPE_U32:
        ares_dns_rr_set_u32(rr, keys[i], take32(c));
        break;
      case ARES_DATATYPE_NAME:
      case ARES_DATATYPE_STR:
        take_blob(c, blob, MAX_STR);
        ares_dns_rr_set_str(rr, keys[i], (const char *)blob);
        break;
      case ARES_DATATYPE_BIN:
      case ARES_DATATYPE_BINP:
        bloblen = take_blob(c, blob, MAX_BLOB);
        ares_dns_rr_set_bin(rr, keys[i], blob, bloblen);
        break;
      case ARES_DATATYPE_ABINP:
        {
          unsigned int n = take8(c) % 3u;
          unsigned int a;
          for (a = 0; a < n; a++) {
            bloblen = take_blob(c, blob, MAX_BLOB);
            ares_dns_rr_add_abin(rr, keys[i], blob, bloblen);
          }
          break;
        }
      case ARES_DATATYPE_OPT:
        {
          unsigned int n = take8(c) % 3u;
          unsigned int a;
          for (a = 0; a < n; a++) {
            unsigned short opt = (unsigned short)take16(c);
            bloblen            = take_blob(c, blob, 64);
            ares_dns_rr_set_opt(rr, keys[i], opt, blob, bloblen);
          }
          break;
        }
      default:
        break;
    }
  }
}
