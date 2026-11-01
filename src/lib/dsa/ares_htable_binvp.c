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
#include "ares_private.h"
#include "ares_htable.h"
#include "ares_htable_binvp.h"

struct ares_htable_binvp {
  ares_htable_binvp_val_free_t free_val;
  ares_htable_t               *hash;
};

typedef struct {
  const unsigned char *data;
  size_t               len;
} ares_htable_binvp_key_t;

typedef struct {
  ares_htable_binvp_key_t key;
  unsigned char          *key_data;
  void                   *val;
  ares_htable_binvp_t    *parent;
} ares_htable_binvp_bucket_t;

void ares_htable_binvp_destroy(ares_htable_binvp_t *htable)
{
  if (htable == NULL) {
    return;
  }

  ares_htable_destroy(htable->hash);
  ares_free(htable);
}

static unsigned int hash_func(const void *key, unsigned int seed)
{
  const ares_htable_binvp_key_t *arg = key;
  return ares_htable_hash_FNV1a(arg->data, arg->len, seed);
}

static const void *bucket_key(const void *bucket)
{
  const ares_htable_binvp_bucket_t *arg = bucket;
  return &arg->key;
}

static void bucket_free(void *bucket)
{
  ares_htable_binvp_bucket_t *arg = bucket;

  if (arg->parent->free_val != NULL) {
    arg->parent->free_val(arg->val);
  }

  ares_free(arg->key_data);
  ares_free(arg);
}

static ares_bool_t key_eq(const void *key1, const void *key2)
{
  const ares_htable_binvp_key_t *k1 = key1;
  const ares_htable_binvp_key_t *k2 = key2;

  if (k1->len != k2->len) {
    return ARES_FALSE;
  }

  if (k1->len == 0) {
    return ARES_TRUE;
  }

  return memcmp(k1->data, k2->data, k1->len) == 0 ? ARES_TRUE : ARES_FALSE;
}

ares_htable_binvp_t *
  ares_htable_binvp_create(ares_htable_binvp_val_free_t val_free)
{
  ares_htable_binvp_t *htable = ares_malloc_zero(sizeof(*htable));

  if (htable == NULL) {
    goto fail;
  }

  htable->free_val = val_free;
  htable->hash = ares_htable_create(hash_func, bucket_key, bucket_free, key_eq);
  if (htable->hash == NULL) {
    goto fail;
  }

  return htable;

fail:
  ares_htable_binvp_destroy(htable);
  return NULL;
}

ares_bool_t ares_htable_binvp_insert(ares_htable_binvp_t *htable,
                                     const unsigned char *key, size_t key_len,
                                     void *val)
{
  ares_htable_binvp_bucket_t *bucket = NULL;

  if (htable == NULL || (key == NULL && key_len != 0)) {
    goto fail;
  }

  bucket = ares_malloc_zero(sizeof(*bucket));
  if (bucket == NULL) {
    goto fail;
  }

  if (key_len != 0) {
    bucket->key_data = ares_malloc(key_len);
    if (bucket->key_data == NULL) {
      goto fail;
    }
    memcpy(bucket->key_data, key, key_len);
  }

  bucket->key.data = bucket->key_data;
  bucket->key.len  = key_len;
  bucket->parent   = htable;
  bucket->val      = val;

  if (!ares_htable_insert(htable->hash, bucket)) {
    goto fail;
  }

  return ARES_TRUE;

fail:
  if (bucket != NULL) {
    ares_free(bucket->key_data);
    ares_free(bucket);
  }
  return ARES_FALSE;
}

ares_bool_t ares_htable_binvp_get(const ares_htable_binvp_t *htable,
                                  const unsigned char *key, size_t key_len,
                                  void **val)
{
  ares_htable_binvp_key_t     lookup;
  ares_htable_binvp_bucket_t *bucket;

  if (val != NULL) {
    *val = NULL;
  }

  if (htable == NULL || (key == NULL && key_len != 0)) {
    return ARES_FALSE;
  }

  lookup.data = key;
  lookup.len  = key_len;
  bucket      = ares_htable_get(htable->hash, &lookup);
  if (bucket == NULL) {
    return ARES_FALSE;
  }

  if (val != NULL) {
    *val = bucket->val;
  }
  return ARES_TRUE;
}

void *ares_htable_binvp_get_direct(const ares_htable_binvp_t *htable,
                                   const unsigned char *key, size_t key_len)
{
  void *val = NULL;
  ares_htable_binvp_get(htable, key, key_len, &val);
  return val;
}

ares_bool_t ares_htable_binvp_remove(ares_htable_binvp_t *htable,
                                     const unsigned char *key, size_t key_len)
{
  ares_htable_binvp_key_t lookup;

  if (htable == NULL || (key == NULL && key_len != 0)) {
    return ARES_FALSE;
  }

  lookup.data = key;
  lookup.len  = key_len;
  return ares_htable_remove(htable->hash, &lookup);
}

size_t ares_htable_binvp_num_keys(const ares_htable_binvp_t *htable)
{
  if (htable == NULL) {
    return 0;
  }
  return ares_htable_num_keys(htable->hash);
}
