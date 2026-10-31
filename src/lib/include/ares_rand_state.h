/* MIT License
 *
 * Copyright (c) The c-ares project and its contributors
 *
 * SPDX-License-Identifier: MIT
 */

#ifndef __ARES_RAND_STATE_H
#define __ARES_RAND_STATE_H

/* Random state used for query IDs, DNS0x20 casing, and cookies. */

struct ares_rand_state;
typedef struct ares_rand_state ares_rand_state;

/* Bits for ares_init_rand_state_skip(). They match ares_rand_backend in
 * util/ares_rand.c: the OS random source and the entropy file. */
#define ARES_RAND_SKIP_OS   (1U << 0)
#define ARES_RAND_SKIP_FILE (1U << 1)

/*! Create a random state, treating the backends in skip_backends (a mask of
 *  ARES_RAND_SKIP_* bits) as unavailable. Test seam for the fail-closed path.
 *
 *  \param[in]  skip_backends  Mask of ARES_RAND_SKIP_* bits
 *  \param[out] no_entropy     Set to ARES_TRUE when no entropy source is left
 *  \return new state, or NULL on failure
 */
CARES_EXTERN ares_rand_state *ares_init_rand_state_skip(unsigned int skip_backends,
                                                        ares_bool_t *no_entropy);

/*! Destroy a random state created by ares_init_rand_state() or
 *  ares_init_rand_state_skip(). Safe to call with NULL.
 *
 *  \param[in] state  Random state to destroy
 */
CARES_EXTERN void ares_destroy_rand_state(ares_rand_state *state);

#endif /* __ARES_RAND_STATE_H */
