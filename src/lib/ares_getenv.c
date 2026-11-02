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
#include "ares_getenv.h"

#ifdef HAVE_STDLIB_H
#  include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#  include <unistd.h>
#endif

/* Like the system resolver, ignore the environment in setuid/setgid (or
 * otherwise privilege-elevated) processes, where it is controlled by a less
 * privileged user. */
const char *ares_getenv(const char *name)
{
#if defined(HAVE_SECURE_GETENV)
  return secure_getenv(name);
#elif defined(HAVE_ISSETUGID)
  /* LCOV_EXCL_START: FallbackCode */
  if (issetugid()) {
    return NULL;
  }
  return getenv(name);
  /* LCOV_EXCL_STOP */
#elif defined(HAVE_GETENV)
  /* LCOV_EXCL_START: FallbackCode */
  return getenv(name);
  /* LCOV_EXCL_STOP */
#else
  /* LCOV_EXCL_START: FallbackCode */
  (void)name;
  return NULL;
  /* LCOV_EXCL_STOP */
#endif
}
