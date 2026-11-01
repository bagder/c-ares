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
#ifndef __ARES__HTABLE_BINVP_H
#define __ARES__HTABLE_BINVP_H

/*! \addtogroup ares_htable_binvp HashTable with binary Key and void pointer
 * Value
 *
 * This data structure wraps ares_htable with copied, variable-length binary
 * keys. Keys are compared by length and all bytes, including embedded zeros.
 * A zero-length key is valid and may be passed as NULL; all zero-length keys
 * are equal. A NULL key with a nonzero length is invalid.
 *
 * Hashing and copying a key take O(key_len) time. Hash table insertion, search,
 * and deletion have average O(1) time apart from key processing.
 *
 * @{
 */

struct ares_htable_binvp;

/*! Opaque data type for binary key, void pointer hash table implementation. */
typedef struct ares_htable_binvp ares_htable_binvp_t;

/*! Callback to free a stored value on replacement, removal, or destruction.
 *
 *  \param[in] val User-supplied value, which may be NULL.
 */
typedef void (*ares_htable_binvp_val_free_t)(void *val);

/*! Create a binary key, void pointer value hash table.
 *
 *  \param[in] val_free Optional callback to free values. If NULL, the caller
 *                      remains responsible for freeing stored values.
 *  \return Initialized hash table, or NULL on allocation failure.
 */
CARES_EXTERN ares_htable_binvp_t *
  ares_htable_binvp_create(ares_htable_binvp_val_free_t val_free);

/*! Destroy the hash table, its copied keys, and its stored values.
 *
 *  \param[in] htable Hash table to destroy. NULL is allowed and does nothing.
 */
CARES_EXTERN void ares_htable_binvp_destroy(ares_htable_binvp_t *htable);

/*! Insert or replace a key/value pair. The key is copied. On success the table
 *  takes ownership of the value; replacement frees the previous value using
 *  val_free, if supplied. On failure, the caller retains ownership of val and
 *  an existing value for the key is unchanged.
 *
 *  \param[in] htable  Initialized hash table.
 *  \param[in] key     Bytes to associate with value. May be NULL if key_len is
 * 0.
 *  \param[in] key_len Number of bytes in key.
 *  \param[in] val     Value to store, which may be NULL.
 *  \return ARES_TRUE on success; ARES_FALSE for invalid input or allocation
 *          failure.
 */
CARES_EXTERN ares_bool_t ares_htable_binvp_insert(ares_htable_binvp_t *htable,
                                                  const unsigned char *key,
                                                  size_t key_len, void *val);

/*! Retrieve a value by key without transferring ownership.
 *
 *  \param[in]  htable  Initialized hash table.
 *  \param[in]  key     Bytes to search for. May be NULL if key_len is 0.
 *  \param[in]  key_len Number of bytes in key.
 *  \param[out] val     Optional output for the value. Set to NULL on failure.
 *  \return ARES_TRUE if the key exists, even if its value is NULL; ARES_FALSE
 *          for a missing key or invalid input.
 */
CARES_EXTERN ares_bool_t
  ares_htable_binvp_get(const ares_htable_binvp_t *htable,
                        const unsigned char *key, size_t key_len, void **val);

/*! Retrieve a value directly without transferring ownership. Unlike get(),
 *  this function cannot distinguish a missing key from a stored NULL value.
 *
 *  \param[in] htable  Initialized hash table.
 *  \param[in] key     Bytes to search for. May be NULL if key_len is 0.
 *  \param[in] key_len Number of bytes in key.
 *  \return Stored value, or NULL for a missing key or invalid input.
 */
CARES_EXTERN void *
  ares_htable_binvp_get_direct(const ares_htable_binvp_t *htable,
                               const unsigned char *key, size_t key_len);

/*! Remove a key and free its copied bytes and stored value using val_free,
 *  if supplied.
 *
 *  \param[in] htable  Initialized hash table.
 *  \param[in] key     Bytes to search for. May be NULL if key_len is 0.
 *  \param[in] key_len Number of bytes in key.
 *  \return ARES_TRUE if removed; ARES_FALSE for a missing key or invalid input.
 */
CARES_EXTERN ares_bool_t ares_htable_binvp_remove(ares_htable_binvp_t *htable,
                                                  const unsigned char *key,
                                                  size_t               key_len);

/*! Retrieve the number of distinct keys stored in the hash table.
 *
 *  \param[in] htable Initialized hash table, or NULL.
 *  \return Number of keys, or 0 if htable is NULL.
 */
CARES_EXTERN size_t
  ares_htable_binvp_num_keys(const ares_htable_binvp_t *htable);

/*! @} */

#endif /* __ARES__HTABLE_BINVP_H */
