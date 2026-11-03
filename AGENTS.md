# AGENTS.md — c-ares rules for coding agents

c-ares is critical infrastructure (curl, Node.js, ...).  Correctness,
portability, and interoperability beat cleverness.  Contribution policy
(coverage >90%, API/ABI rules, commit format) lives in
`CONTRIBUTING.md` — read it.  Build-system notes: `DEVELOPER-NOTES.md`.

## Hard rules

1. **C89.** Declarations before statements, `/* */` comments, no VLAs.
   Only extension allowed: 64-bit ints.  clang/gcc won't catch
   declaration-order mistakes; the OpenWatcom CI job will.
2. **No API/ABI breaks** — see `CONTRIBUTING.md` for the exact policy,
   including the limited `ares_options` extension criteria.
3. **Never hand-roll data structures, algorithms, or parsing.**  Use
   the internal library (table below).  If it lacks something, extend
   it with a general, documented, tested helper — no one-offs.  All
   parsing/serialization goes through `ares_buf_*()`.
4. **OOM returns errors** (`ARES_ENOMEM`), never crashes.  Annotate the
   untestable failure path: `/* LCOV_EXCL_LINE: OutOfMemory */`.
5. **Tests required**; coverage must stay >90% (`CONTRIBUTING.md`).
   Prefer tests that fail without your change.
6. **clang-format** (>= 20) on changed lines, CI-enforced.  Run
   `git clang-format` before pushing; never hand-align.
7. **Never break interoperability.**  Parse tolerantly, emit
   conservatively; justify any parser strictness increase.  Cite the
   RFC section in a comment next to protocol behavior.

## Build and test

```sh
cmake -DCMAKE_BUILD_TYPE=DEBUG -DCARES_BUILD_TESTS=ON -G Ninja -B build
ninja -C build
./build/bin/arestest -4 --gtest_filter='<Pattern>'
```

- Always filter tests (full suite is slow; `-*Live*` skips network).
- Both CMake and autotools must keep working; add new files to
  `src/lib/Makefile.inc`.
- CI is wide: -Werror on modern toolchains, ASAN/UBSAN/valgrind/
  scan-build, plus old gcc, MSVC, MinGW, OpenWatcom, DJGPP, musl,
  Android/iOS, BSDs, Solaris, QNX.

## Code conventions

- `#include "ares_private.h"` first in every `src/lib` `.c`; system
  headers after, in `#ifdef HAVE_*` guards.
- Memory: `ares_malloc/ares_malloc_zero/ares_realloc_zero/ares_free/
  ares_strdup` only.  Multiplied allocation sizes must be
  overflow-checked (`ares_malloc_array`, `ares_realloc_array`,
  `ares_malloc_zero_array`, `ares_realloc_zero_array`, or
  `ares_size_t_mul_overflow`).  Never `malloc(0)`.
- Safe Buffers: sources listed in `CARES_SAFE_BUFFERS_SOURCES`
  (`src/lib/CMakeLists.txt`) build with clang's `-Wunsafe-buffer-usage`,
  so no pointer arithmetic and no indexing through raw pointers there.
  Add a file to the list once it builds clean.
- Errors: return `ares_status_t`; single-exit `goto done` cleanup.
- Strings/ctype: `ares_str.h` helpers (`ares_streq`, `ares_strcaseeq`,
  `ares_isdigit`, `ares_str_parse_uint`, ...).  libc `str*`, `atoi`,
  and `<ctype.h>` are locale-sensitive — don't use them.
- `ares_rand_bytes()` never `rand()`; `ares_tvnow()`/`ares_timeval_*`
  for all timeout math (monotonic).
- Types: `size_t` for sizes/counts, `unsigned char *` for bytes,
  `ares_bool_t` for booleans; `-Wconversion -Wsign-conversion` are on.
- Visibility: `static` by default.  `CARES_EXTERN` only in public
  headers and the semi-public `src/lib/include/` headers.
- Locking: public entry points take `ares_channel_lock()`; internals
  that expect the lock held use the `*_nolock` suffix.
- New files: MIT license header with the SPDX MIT identifier tag
  (REUSE CI-enforced; copy the header from `src/lib/ares_cookie.c`),
  add to `Makefile.inc` + CMake.
- **Doxygen-style comment on every function** in headers:
  `/*! Description \param[in] x desc \return desc */` — match
  `src/lib/include/ares_buf.h`.

## Internal library — use it or extend it

| Need | Use | Never |
|---|---|---|
| Parse/build wire or text data | `ares_buf` (fetch/consume/tag/split/append) | pointer-walking, manual length checks |
| Strings | `ares_str.h`, `ares_strsplit` | libc `str*`/`strtok`/`atoi` |
| Dynamic array | `ares_array` | `realloc`-grown arrays |
| List/queue | `ares_llist` | hand-rolled lists |
| Sorted collection | `ares_slist` (skip list) | sorted-insert loops |
| Hash map | `ares_htable_{strvp,szvp,asvp,dict,vpvp,vpstr}` (add a typed wrapper if your combo is missing) | linear-scan tables |
| DNS messages | `ares_dns_record` parse/write/dup; new RR types via `ares_dns_mapping.c` tables; TXT via `ares_dns_multistring` | raw byte poking; extending `src/lib/legacy/` |
| URIs, host:port strings | `ares_uri` | `sscanf`/`strchr` surgery |
| Math/overflow | `ares_math.h` | unchecked multiplies |
| Threads/events/interfaces | `ares_threads.h`, `ares_event*`, `ares_iface_ips` | direct pthread/Win32/getifaddrs |

Also exists: `ares_qcache`, `ares_cookie`, `ares_metrics`,
`ares_addrinfo*` (RFC 6724 sort).  Precedent: `ares_str_parse_uint()`
and `ares_size_t_mul_overflow()` were added as shared helpers instead
of open-coding — do likewise, and convert identical sibling call sites.

## Tests

- Placement: internal/unit → `test/ares-test-internal.cc` (wrap
  non-`CARES_EXTERN` calls in `#ifndef CARES_SYMBOL_HIDING`); mock DNS
  server → `ares-test-mock*.cc` (`-et` event-thread, `-ai`
  getaddrinfo); config/init + container tests → `ares-test-init.cc`;
  legacy parsers → `ares-test-parse-*.cc`.
- Fixtures in `test/ares-test.h`: `LibraryTest` (has `SetAllocFail` for
  OOM testing), `DefaultChannelTest`, `MockChannelOptsTest`, ...
- Container tests (`CONTAINED_TEST_F`) are Linux-only.
- LCOV exclusion tags: only `OutOfMemory`, `DefensiveCoding`,
  `UntestablePath`, `FallbackCode` (see `CONTRIBUTING.md`).
- Parser/writer changes: the fuzzer round-trips
  `ares_dns_parse`→`ares_dns_write` (`test/ares-test-fuzz.c`); add
  corpus entries in `test/fuzzinput/` for new record types.

## Docs

- Public API change ⇒ update `docs/` man page in the same PR.  Families
  share a grouped page with `.so man3/<group>.3` stubs per symbol
  (e.g. `docs/ares_dns_mapping.3`); standalone functions get their own
  page.
- Don't touch `RELEASE-NOTES.md`.

## Security

- All parsed input is untrusted; length-check via `ares_buf`.
- In PR descriptions, distinguish remote (DNS wire) vs local
  (config/env/API) attack surfaces honestly; local-config hardening is
  not a "security fix".
- Suspected vulnerabilities go through `SECURITY.md`, not public PRs.
