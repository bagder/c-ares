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
#include "ares-test.h"
#include "dns-proto.h"

#include <climits>
#include <cstdint>
#include <stdio.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifdef HAVE_SYS_IOCTL_H
#  include <sys/ioctl.h>
#endif
extern "C" {
// Remove command-line defines of package variables for the test project...
#undef PACKAGE_NAME
#undef PACKAGE_BUGREPORT
#undef PACKAGE_STRING
#undef PACKAGE_TARNAME
// ... so we can include the library's config without symbol redefinitions.
#include "ares_private.h"
#include "ares_inet_net_pton.h"
#include "ares_data.h"
#include "str/ares_strsplit.h"
#include "ares_punycode.h"
#include "str/ares_idnamap.h"
#include "dsa/ares_htable.h"

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_UIO_H
#  include <sys/uio.h>
#endif
}

#include <string>
#include <vector>

namespace ares {
namespace test {

#ifndef CARES_SYMBOL_HIDING
TEST_F(LibraryTest, StringLength) {
  const char data[] = "test\0test";
  size_t n = sizeof data;
  for(size_t i = 0; i < n; ++i) {
    EXPECT_EQ(ares_strlen(&data[i]), ares_strnlen(&data[i], n - i));
  }
}

TEST_F(LibraryTest, StringLengthNullPointer) {
  EXPECT_EQ(ares_strlen(NULL), 0);
  EXPECT_EQ(ares_strnlen(NULL, 0), 0);
  EXPECT_EQ(ares_strnlen(NULL, 1), 0);
  EXPECT_EQ(ares_strnlen(NULL, 42), 0);
}

TEST_F(LibraryTest, StringLengthWithoutNullTerminator) {
  std::string data = "test";
  for(size_t i = 0; i < data.length(); ++i) {
    EXPECT_EQ(ares_strnlen(data.c_str(), i), i);
  }
}

TEST_F(LibraryTest, StrParseUint) {
  unsigned int v = 42;

  EXPECT_TRUE(ares_str_parse_uint("0", 128, &v));
  EXPECT_EQ(0u, v);
  EXPECT_TRUE(ares_str_parse_uint("128", 128, &v));
  EXPECT_EQ(128u, v);

  // Exactly UINT_MAX is accepted (the interesting boundary: on a 32-bit
  // unsigned long it parses to ULONG_MAX without ERANGE).
  EXPECT_TRUE(ares_str_parse_uint("4294967295", UINT_MAX, &v));
  EXPECT_EQ(UINT_MAX, v);

  // max == 0 permits only "0".
  EXPECT_TRUE(ares_str_parse_uint("0", 0, &v));
  EXPECT_EQ(0u, v);

  // Failure leaves *out untouched.
  v = 42;
  EXPECT_FALSE(ares_str_parse_uint("1", 0, &v));
  EXPECT_EQ(42u, v);
  EXPECT_FALSE(ares_str_parse_uint("129", 128, &v));
  EXPECT_EQ(42u, v);

  EXPECT_FALSE(ares_str_parse_uint("4294967296", UINT_MAX, &v)); // over on LP64
  EXPECT_FALSE(ares_str_parse_uint("12x", UINT_MAX, &v));        // trailing
  EXPECT_FALSE(ares_str_parse_uint("0x10", UINT_MAX, &v));       // trailing hex
  EXPECT_FALSE(ares_str_parse_uint(" 5", UINT_MAX, &v));         // leading space
  EXPECT_FALSE(ares_str_parse_uint("+5", UINT_MAX, &v));         // leading sign
  EXPECT_FALSE(ares_str_parse_uint("-1", UINT_MAX, &v));         // sign wrap
  EXPECT_FALSE(ares_str_parse_uint("", UINT_MAX, &v));
  EXPECT_FALSE(ares_str_parse_uint(NULL, UINT_MAX, &v));
}

void CheckPtoN4(int size, unsigned int value, const char *input) {
  struct in_addr a4;
  a4.s_addr = 0;
  uint32_t expected = htonl(value);
  EXPECT_EQ(size, ares_inet_net_pton(AF_INET, input, &a4, sizeof(a4)))
    << " for input " << input;
  EXPECT_EQ(expected, a4.s_addr) << " for input " << input;
}

TEST_F(LibraryTest, Strsplit) {
  using std::vector;
  using std::string;
  size_t n;
  struct {
    vector<string> inputs;
    vector<string> delimiters;
    vector<vector<string>> expected;
  } data = {
    {
      "",
      " ",
      "             ",
      "example.com, example.co",
      "        a, b, A,c,     d, e,,,D,e,e,E",
    },
    { ", ", ", ", ", ", ", ", ", " },
    {
      {}, {}, {},
      { "example.com", "example.co" },
      { "a", "b", "c", "d", "e" },
    },
  };
  for(size_t i = 0; i < data.inputs.size(); i++) {
    char **out = ares_strsplit(data.inputs.at(i).c_str(),
                               data.delimiters.at(i).c_str(), &n);
    if(data.expected.at(i).size() == 0) {
      EXPECT_EQ(out, nullptr);
    }
    else {
      EXPECT_EQ(n, data.expected.at(i).size());
      for(size_t j = 0; j < n && j < data.expected.at(i).size(); j++) {
        EXPECT_STREQ(out[j], data.expected.at(i).at(j).c_str());
      }
    }
    ares_strsplit_free(out, n);
  }
}

TEST_F(LibraryTest, InetNetPtoN) {
  uint32_t expected;
  struct in_addr a4;
  struct in6_addr a6;
  CheckPtoN4(4 * 8, 0x01020304, "1.2.3.4");
  CheckPtoN4(4 * 8, 0x81010101, "129.1.1.1");
  CheckPtoN4(4 * 8, 0xC0010101, "192.1.1.1");
  CheckPtoN4(4 * 8, 0xE0010101, "224.1.1.1");
  CheckPtoN4(4 * 8, 0xE1010101, "225.1.1.1");
  CheckPtoN4(4, 0xE0000000, "224");
  CheckPtoN4(4 * 8, 0xFD000000, "253");
  CheckPtoN4(4 * 8, 0xF0010101, "240.1.1.1");
  CheckPtoN4(4 * 8, 0x02030405, "02.3.4.5");
  CheckPtoN4(3 * 8, 0x01020304, "1.2.3.4/24");
  CheckPtoN4(3 * 8, 0x01020300, "1.2.3/24");
  CheckPtoN4(2 * 8, 0xa0000000, "0xa");
  CheckPtoN4(0, 0x02030405, "2.3.4.5/000");
  CheckPtoN4(1 * 8, 0x01020000, "1.2/8");
  CheckPtoN4(2 * 8, 0x01020000, "0x0102/16");
  CheckPtoN4(4 * 8, 0x02030405, "02.3.4.5");

  // Partially specified
  // (ensures 4 octets are properly zeroed)
  a4.s_addr = 0xFFFFFFFF;
  ares_inet_net_pton(AF_INET, "10/8", &a4, sizeof(a4));
  EXPECT_EQ(htonl(0x0A000000), a4.s_addr);

  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "::", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "::1", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "1234:5678::", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(23, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4/23", &a6, sizeof(a6)));
  EXPECT_EQ(3 * 8, ares_inet_net_pton(AF_INET6, "12:34::ff/24", &a6, sizeof(a6)));
  EXPECT_EQ(0, ares_inet_net_pton(AF_INET6, "12:34::ff/0", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "12:34::ffff:0.2", &a6, sizeof(a6)));
  EXPECT_EQ(16 * 8, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234", &a6, sizeof(a6)));
  EXPECT_EQ(2, ares_inet_net_pton(AF_INET6, "0::00:00:00/2", &a6, sizeof(a6)));

  // Various malformed versions
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, " ", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x ", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "x0", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0xXYZZY", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "xyzzy", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET+AF_INET6, "1.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "257.2.3.4", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "002.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "00.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5.6", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5.6/12", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4:5", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5/120", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5/1x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "2.3.4.5/x", &a4, sizeof(a4)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/240", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/02", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/2y", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/y", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff/", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":x", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ": :1234", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "::12345", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234::2345:3456::0011", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234::", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":1234:1234:1234:1234:1234:1234:1234:1234", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, ":1234:1234:1234:1234:1234:1234:1234:1234:", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "1234:1234:1234:1234:1234:1234:1234:1234:5678:5678:5678", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:257.2.3.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4.5.6", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.4.5", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.z", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3001.4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3..4", &a6, sizeof(a6)));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ffff:1.2.3.", &a6, sizeof(a6)));

  // Hex constants are allowed.
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x01020304", &a4, sizeof(a4)));
  expected = htonl(0x01020304);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x0a0b0c0d", &a4, sizeof(a4)));
  expected = htonl(0x0a0b0c0d);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x0A0B0C0D", &a4, sizeof(a4)));
  expected = htonl(0x0a0b0c0d);
  EXPECT_EQ(expected, a4.s_addr);
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x0xyz", &a4, sizeof(a4)));
  EXPECT_EQ(4 * 8, ares_inet_net_pton(AF_INET, "0x1122334", &a4, sizeof(a4)));
  expected = htonl(0x11223340);
  EXPECT_EQ(expected, a4.s_addr);  // huh?

  // No room, no room.
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "1.2.3.4", &a4, sizeof(a4) - 1));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET6, "12:34::ff", &a6, sizeof(a6) - 1));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x01020304", &a4, 2));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x01020304", &a4, 0));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x0a0b0c0d", &a4, 0));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x0xyz", &a4, 0));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "0x1122334", &a4, sizeof(a4) - 1));
  EXPECT_EQ(-1, ares_inet_net_pton(AF_INET, "253", &a4, sizeof(a4) - 1));
}

// An IPv6 network with a prefix length only carries (bits+7)/8 bytes; the
// rest of the destination must be zeroed rather than left as it was.
TEST_F(LibraryTest, InetNetPtoNPrefixZeroFills) {
  unsigned char a6[16];

  memset(a6, 0x41, sizeof(a6));
  EXPECT_EQ(0, ares_inet_net_pton(AF_INET6, "::1/0", a6, sizeof(a6)));
  EXPECT_EQ("0000:0000:0000:0000:0000:0000:0000:0000",
            AddressToString(a6, 16));

  memset(a6, 0x41, sizeof(a6));
  EXPECT_EQ(64, ares_inet_net_pton(AF_INET6, "2001:db8:1:2:3:4:5:6/64", a6,
                                   sizeof(a6)));
  EXPECT_EQ("2001:0db8:0001:0002:0000:0000:0000:0000",
            AddressToString(a6, 16));
}

TEST_F(LibraryTest, FreeLongChain) {
  struct ares_addr_node *data = nullptr;
  for (int ii = 0; ii < 100000; ii++) {
    struct ares_addr_node *prev = (struct ares_addr_node*)ares_malloc_data(ARES_DATATYPE_ADDR_NODE);
    prev->next = data;
    data = prev;
  }

  ares_free_data(data);
}

TEST_F(LibraryTest, MallocDataFail) {
  EXPECT_EQ(nullptr, ares_malloc_data((ares_datatype)99));
  SetAllocSizeFail(sizeof(struct ares_data));
  EXPECT_EQ(nullptr, ares_malloc_data(ARES_DATATYPE_MX_REPLY));
}

TEST(Misc, OnionDomain) {
  EXPECT_EQ(0, ares_is_onion_domain("onion.no"));
  EXPECT_EQ(0, ares_is_onion_domain(".onion.no"));
  EXPECT_EQ(1, ares_is_onion_domain(".onion"));
  EXPECT_EQ(1, ares_is_onion_domain(".onion."));
  EXPECT_EQ(1, ares_is_onion_domain("yes.onion"));
  EXPECT_EQ(1, ares_is_onion_domain("yes.onion."));
  EXPECT_EQ(1, ares_is_onion_domain("YES.ONION"));
  EXPECT_EQ(1, ares_is_onion_domain("YES.ONION."));
}

TEST_F(LibraryTest, CatDomain) {
  char *s;

  ares_cat_domain("foo", "example.net", &s);
  EXPECT_STREQ("foo.example.net", s);
  ares_free(s);

  ares_cat_domain("foo", ".", &s);
  EXPECT_STREQ("foo.", s);
  ares_free(s);

  ares_cat_domain("foo", "example.net.", &s);
  EXPECT_STREQ("foo.example.net.", s);
  ares_free(s);
}

TEST_F(LibraryTest, SlistMisuse) {
  EXPECT_EQ(NULL, ares_slist_create(NULL, NULL, NULL));
  ares_slist_replace_destructor(NULL, NULL);
  EXPECT_EQ(NULL, ares_slist_insert(NULL, NULL));
  EXPECT_EQ(NULL, ares_slist_node_find(NULL, NULL));
  EXPECT_EQ(NULL, ares_slist_node_first(NULL));
  EXPECT_EQ(NULL, ares_slist_node_last(NULL));
  EXPECT_EQ(NULL, ares_slist_node_next(NULL));
  EXPECT_EQ(NULL, ares_slist_node_prev(NULL));
  EXPECT_EQ(NULL, ares_slist_node_val(NULL));
  EXPECT_EQ((size_t)0, ares_slist_len(NULL));
  EXPECT_EQ(NULL, ares_slist_node_parent(NULL));
  EXPECT_EQ(NULL, ares_slist_first_val(NULL));
  EXPECT_EQ(NULL, ares_slist_last_val(NULL));
  EXPECT_EQ(NULL, ares_slist_node_claim(NULL));
}

#if !defined(_WIN32) || _WIN32_WINNT >= 0x0600
TEST_F(LibraryTest, IfaceIPs) {
  ares_status_t      status;
  ares_iface_ips_t *ips = NULL;
  size_t             i;

  status = ares_iface_ips(&ips, ARES_IFACE_IP_DEFAULT, NULL);
  EXPECT_TRUE(status == ARES_SUCCESS || status == ARES_ENOTIMP);

  /* Not implemented, can't run tests */
  if (status == ARES_ENOTIMP)
    return;

  EXPECT_NE(nullptr, ips);

  for (i=0; i<ares_iface_ips_cnt(ips); i++) {
    const char *name = ares_iface_ips_get_name(ips, i);
    EXPECT_NE(nullptr, name);
    int flags = (int)ares_iface_ips_get_flags(ips, i);
    EXPECT_NE(0, (int)flags);
    EXPECT_NE(nullptr, ares_iface_ips_get_addr(ips, i));
    EXPECT_NE(0, ares_iface_ips_get_netmask(ips, i));
    if (flags & ARES_IFACE_IP_LINKLOCAL && flags & ARES_IFACE_IP_V6) {
      /* Hmm, seems not to work at least on MacOS
       * EXPECT_NE(0, ares_iface_ips_get_ll_scope(ips, i));
       */
    } else {
      EXPECT_EQ(0, ares_iface_ips_get_ll_scope(ips, i));
    }
    unsigned int idx = ares_os_if_nametoindex(name);
    EXPECT_NE(0, idx);
    char namebuf[256];
    EXPECT_EQ(std::string(ares_os_if_indextoname(idx, namebuf, sizeof(namebuf))), std::string(name));
  }


  /* Negative checking */
  ares_iface_ips_get_name(ips, ares_iface_ips_cnt(ips));
  ares_iface_ips_get_flags(ips, ares_iface_ips_cnt(ips));
  ares_iface_ips_get_addr(ips, ares_iface_ips_cnt(ips));
  ares_iface_ips_get_netmask(ips, ares_iface_ips_cnt(ips));
  ares_iface_ips_get_ll_scope(ips, ares_iface_ips_cnt(ips));

  ares_iface_ips(NULL, ARES_IFACE_IP_DEFAULT, NULL);
  ares_iface_ips_cnt(NULL);
  ares_iface_ips_get_name(NULL, 0);
  ares_iface_ips_get_flags(NULL, 0);
  ares_iface_ips_get_addr(NULL, 0);
  ares_iface_ips_get_netmask(NULL, 0);
  ares_iface_ips_get_ll_scope(NULL, 0);
  ares_iface_ips_destroy(NULL);
  ares_os_if_nametoindex(NULL);
  ares_os_if_indextoname(0, NULL, 0);

  ares_iface_ips_destroy(ips);
}
#endif

TEST_F(LibraryTest, HtableMisuse) {
  EXPECT_EQ(NULL, ares_htable_create(NULL, NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_insert(NULL, NULL));
  EXPECT_EQ(NULL, ares_htable_get(NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares_htable_num_keys(NULL));
}

TEST_F(LibraryTest, URI) {
  struct {
    ares_bool_t success;
    const char *uri;
    const char *alt_match_uri;
  } tests[] = {
    { ARES_TRUE,  "https://www.example.com",                                                               NULL },
    { ARES_TRUE,  "https://www.example.com:8443",                                                          NULL },
    { ARES_TRUE,  "https://user:password@www.example.com",                                                 NULL },
    { ARES_TRUE,  "https://user%25:password@www.example.com",                                              NULL },
    { ARES_TRUE,  "https://user:password%25@www.example.com",                                              NULL },
    { ARES_TRUE,  "https://user@www.example.com",                                                          NULL },
    { ARES_TRUE,  "https://user@www.example.com:8443",                                                     NULL },
    { ARES_TRUE,  "dns://user@[fe80::1]:53",                                                               NULL },
    { ARES_FALSE, "https://user@www.example.com:8443@evil.example.com",                                    NULL }, /* ambiguous authority, '@' not valid in host */
    { ARES_TRUE,  "https://www.example.com/path",                                                          NULL },
    { ARES_TRUE,  "https://www.example.com/path/",                                                         NULL },
    { ARES_TRUE,  "https://www.example.com/a/../",                                                         "https://www.example.com/" },
    { ARES_TRUE,  "https://www.example.com/../a/",                                                         "https://www.example.com/a/" },
    { ARES_TRUE,  "https://www.example.com/.././../a/",                                                    "https://www.example.com/a/" },
    { ARES_TRUE,  "https://www.example.com/.././../a//b/c/d/../../",                                       "https://www.example.com/a/b/" },
    { ARES_TRUE,  "https://www.example.com?key=val",                                                       NULL },
    { ARES_TRUE,  "https://www.example.com?key",                                                           NULL },
    { ARES_TRUE,  "https://www.example.com?key=",                                                          "https://www.example.com?key" },
    { ARES_TRUE,  "https://www.example.com#fragment",                                                      NULL },
    { ARES_TRUE,  "https://user:password@www.example.com/path",                                            NULL },
    { ARES_TRUE,  "https://user:password@www.example.com/path#fragment",                                   NULL },
    { ARES_TRUE,  "https://user:password@www.example.com/path?key=val",                                    NULL },
    { ARES_TRUE,  "https://user:password@www.example.com/path?key=val#fragment",                           NULL },
    { ARES_TRUE,  "https://user:password@www.example.com/path?key=val#fragment/with?chars",                NULL },
    { ARES_TRUE,  "HTTPS://www.example.com",                                                               "https://www.example.com" },
    { ARES_TRUE,  "https://www.example.com?key=hello+world",                                               "https://www.example.com?key=hello%20world" },
    { ARES_TRUE,  "https://www.example.com?key=val%26",                                                    NULL },
    { ARES_TRUE,  "https://www.example.com?key%26=val",                                                    NULL },
    { ARES_TRUE,  "https://www.example.com?key=Aa2-._~/?!$'()*,;:@",                                       NULL },
    { ARES_TRUE,  "https://www.example.com?key1=val1&key2=val2&key3=val3&key4=val4",                       "ignore" }, /* keys get randomized, can't match */
    { ARES_TRUE,  "https://www.example.com?key=%41%61%32%2D%2E%5f%7e%2F%3F%21%24%27%28%29%2a%2C%3b%3a%40", "https://www.example.com?key=Aa2-._~/?!$'()*,;:@" },
    { ARES_TRUE,  "dns+tls://192.168.1.1:53",                                                              NULL },
    { ARES_TRUE,  "dns+tls://[fe80::1]:53",                                                                NULL },
    { ARES_TRUE,  "dns://[fe80::b542:84df:1719:65e3%en0]",                                                 NULL },
    { ARES_TRUE,  "dns+tls://[fe80:00::00:1]:53",                                                          "dns+tls://[fe80::1]:53" },
    { ARES_TRUE,  "d.n+s-tls://www.example.com",                                                           NULL },
    { ARES_FALSE, "dns*tls://www.example.com",                                                             NULL }, /* invalid scheme character */
    { ARES_FALSE, "0dns://www.example.com",                                                                NULL }, /* dns can't start with digits */
    { ARES_FALSE, "https://www.example.com?key=val%01",                                                    NULL }, /* non-printable character */
    { ARES_FALSE, "abcdef0123456789://www.example.com",                                                    NULL }, /* scheme too long */
    { ARES_FALSE, "www.example.com",                                                                       NULL }, /* missing scheme */
    { ARES_FALSE, "https://www.example.com?key=val%0",                                                     NULL }, /* truncated uri-encoding */
    { ARES_FALSE, "https://www.example.com?key=val%AZ",                                                    NULL }, /* invalid uri-encoding sequence */
    { ARES_FALSE, "https://www.example.com?key=hello world",                                               NULL }, /* invalid character in query value */
    { ARES_FALSE, "https://:password@www.example.com",                                                     NULL }, /* can't have password without username */
    { ARES_FALSE, "dns+tls://[fe8G::1]",                                                                   NULL }, /* invalid ipv6 address */

    { ARES_FALSE, NULL, NULL }
  };
  size_t i;

  for (i=0; tests[i].uri != NULL; i++) {
    ares_uri_t *uri = NULL;
    ares_status_t status;

    if (verbose) std::cerr << "Testing " << tests[i].uri << std::endl;
    status = ares_uri_parse(&uri, tests[i].uri);
    if (tests[i].success) {
      EXPECT_EQ(ARES_SUCCESS, status);
    } else {
      EXPECT_NE(ARES_SUCCESS, status);
    }

    if (status == ARES_SUCCESS) {
      char *out = NULL;
      EXPECT_EQ(ARES_SUCCESS, ares_uri_write(&out, uri));
      if (tests[i].alt_match_uri == NULL || strcmp(tests[i].alt_match_uri, "ignore") != 0) {
        EXPECT_STRCASEEQ(tests[i].alt_match_uri == NULL?tests[i].uri:tests[i].alt_match_uri, out);
      }
      ares_free(out);
    }
    ares_uri_destroy(uri);
  }

  /* Invalid tests  */
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_scheme(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_scheme(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_username(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_username(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_password(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_password(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_host(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_host(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_port(NULL, 0));
  EXPECT_EQ(0, ares_uri_get_port(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_path(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_path(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_query_key(NULL, NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_del_query_key(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_query_key(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_query_keys(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_set_fragment(NULL, NULL));
  EXPECT_EQ(nullptr, ares_uri_get_fragment(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_write_buf(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_write(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_parse_buf(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_uri_parse_buf(NULL, NULL));
}

TEST_F(LibraryTest, PUNYCODE) {
  struct {
    const char *input;
    const char *output;
  } tests[] = {
    { "www.google.com",      "www.google.com"                   },
    { "www.bücher.com",      "www.xn--bcher-kva.com"            },
    { "www.büücher.com",     "www.xn--bcher-kvaa.com"           },
    { "www.bücüher.com",     "www.xn--bcher-kvab.com"           },
    { "www.bücherü.com",     "www.xn--bcher-kvae.com"           },
    { "www.ýbücher.com",     "www.xn--bcher-kvaf.com"           },
    { "www.übücher.com",     "www.xn--bcher-jvab.com"           },
    { "www.München.com",     "www.xn--Mnchen-3ya.com"           },
    { "www.München-Ost.com", "www.xn--Mnchen-Ost-9db.com"       },
    { "bücher.München.com",  "xn--bcher-kva.xn--Mnchen-3ya.com" },
    { "www.abæcdöef.com",    "www.xn--abcdef-qua4k.com"         },
    { "www.правда.com",      "www.xn--80aafi6cg.com"            },
    { "www.ยจฆฟคฏข.com",     "www.xn--22cdfh1b8fsa.com"         },
    { "www.도메인.com",        "www.xn--hq1bm8jm9l.com"           },
    { "www.ドメイン名例.com",  "www.xn--eckwd4c7cu47r2wf.com"     },
    /* Supplementary plane codepoint exercising 4-byte UTF-8 in both
     * directions: U+10348 GOTHIC LETTER HWAIR */
    { "\xF0\x90\x8D\x88.com", "xn--2c8c.com"                     },
    /* Trailing dot (fully-qualified) round-trips */
    { "www.bücher.com.",     "www.xn--bcher-kva.com."           },
    /* RFC 3492 Section 7.1 sample strings (as single-label domains) */
    /* (B) Chinese (simplified) */
    { "他们为什么不说中文",
      "xn--ihqwcrb4cv8a8dqg056pqjye"                             },
    /* (C) Chinese (traditional) */
    { "他們爲什麽不說中文",
      "xn--ihqwctvzc91f659drss3x8bo0yb"                          },
    /* (D) Czech */
    { "Pročprostěnemluvíčesky",
      "xn--Proprostnemluvesky-uyb24dma41a"                       },
    /* (E) Hebrew */
    { "למההםפשוטלאמדבריםעברית",
      "xn--4dbcagdahymbxekheh6e0a7fei0b"                         },
    /* (G) Japanese */
    { "なぜみんな日本語を話してくれないのか",
      "xn--n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa"               },
    /* (I) Russian */
    { "почемужеонинеговорятпорусски",
      "xn--b1abfaaepdrnnbgefbadotcwatmq2g4l"                     },
    /* (K) Vietnamese */
    { "TạisaohọkhôngthểchỉnóitiếngViệt",
      "xn--TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g"         },
    /* (L) Japanese title with digits in the basic codepoint segment */
    { "3年B組金八先生",
      "xn--3B-ww4c5e180e575a65lsy2b"                             },
    { NULL, NULL }
  };
  size_t i;

  for (i=0; tests[i].input != NULL; i++) {
    ares_status_t status;
    char *encoded = NULL;
    char *decoded = NULL;

    if (verbose) std::cerr << "Testing " << tests[i].input << std::endl;
    status = ares_punycode_encode_domain(tests[i].input, &encoded);
    EXPECT_EQ(ARES_SUCCESS, status);

    if (status == ARES_SUCCESS) {
      EXPECT_STREQ(tests[i].output, encoded);

      status = ares_punycode_decode_domain(tests[i].output, &decoded);
      EXPECT_EQ(ARES_SUCCESS, status);

      EXPECT_STREQ(tests[i].input, decoded);
    }
    ares_free(decoded);
    ares_free(encoded);
  }

  /* The ACE prefix is case-insensitive on decode as per RFC 5890 */
  {
    char *decoded = NULL;
    EXPECT_EQ(ARES_SUCCESS,
              ares_punycode_decode_domain("XN--FSQ.com", &decoded));
    EXPECT_STREQ("例.com", decoded);
    ares_free(decoded);
    decoded = NULL;
    EXPECT_EQ(ARES_SUCCESS,
              ares_punycode_decode_domain("Xn--fsq.com", &decoded));
    EXPECT_STREQ("例.com", decoded);
    ares_free(decoded);
  }

  /* Empty domains trivially round-trip */
  {
    char *out = NULL;
    EXPECT_EQ(ARES_SUCCESS, ares_punycode_encode_domain("", &out));
    EXPECT_STREQ("", out);
    ares_free(out);
    out = NULL;
    EXPECT_EQ(ARES_SUCCESS, ares_punycode_decode_domain("", &out));
    EXPECT_STREQ("", out);
    ares_free(out);
  }

  /* Invalid tests  */
  EXPECT_NE(ARES_SUCCESS, ares_punycode_encode_domain(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_punycode_encode_domain("www.bücher.com", NULL));

  /* Invalid UTF-8 must be rejected, not decoded to garbage */
  struct {
    const char *input;
    const char *descr;
  } invalid_utf8[] = {
    { "www.b\xC3.com",             "truncated 2-byte sequence"          },
    { "www.b\xC3\x28.com",         "invalid continuation byte"          },
    { "www.b\xC0\xAF.com",         "overlong encoding"                  },
    { "www.b\xED\xA0\x80.com",     "UTF-16 surrogate half"              },
    { "www.b\xF4\x90\x80\x80.com", "codepoint beyond U+10FFFF"          },
    { "www.b\xF0\x9F\x98",         "truncated 4-byte sequence at end"   },
    { "www.b\xFF.com",             "invalid lead byte"                  },
    { NULL, NULL }
  };
  for (i=0; invalid_utf8[i].input != NULL; i++) {
    char *encoded = NULL;
    if (verbose) std::cerr << "Testing " << invalid_utf8[i].descr << std::endl;
    EXPECT_NE(ARES_SUCCESS,
              ares_punycode_encode_domain(invalid_utf8[i].input, &encoded))
      << invalid_utf8[i].descr;
    ares_free(encoded);
  }

  /* Invalid punycode decode must error, not emit invalid unicode */
  struct {
    const char *input;
    const char *descr;
  } invalid_puny[] = {
    { "xn--999999999",   "overflow"                          },
    { "xn--a-b!c",       "invalid punycode digit"            },
    { "xn--a-rc4g",      "decodes to a UTF-16 surrogate half" },
    { "xn--9",           "truncated variable-length integer" },
    /* RFC 3492 Section 6.2: the delimiter is only consumed when more than
     * zero basic codepoints precede it; a leading '-' is part of the
     * extended string and is not a valid digit */
    { "xn---baa",        "leading delimiter, no basic codepoints" },
    /* An encoded label longer than the 63 octet DNS limit is rejected
     * before any decode work is performed */
    { "xn--aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "encoded label exceeds 63 octets" },
    { NULL, NULL }
  };
  for (i=0; invalid_puny[i].input != NULL; i++) {
    char *decoded = NULL;
    if (verbose) std::cerr << "Testing " << invalid_puny[i].descr << std::endl;
    EXPECT_NE(ARES_SUCCESS,
              ares_punycode_decode_domain(invalid_puny[i].input, &decoded))
      << invalid_puny[i].descr;
    ares_free(decoded);
  }

  /* Malformed punycode is ARES_EBADNAME specifically: a truncated
   * variable-length integer must not leak the buf layer's ARES_EBADRESP */
  {
    char *decoded = NULL;
    EXPECT_EQ(ARES_EBADNAME, ares_punycode_decode_domain("xn--9", &decoded));
    ares_free(decoded);
  }

  /* A label whose encoded form exceeds the 63 octet DNS limit is rejected */
  {
    std::string toolong;
    char       *encoded = NULL;
    for (i = 0; i < 60; i++) {
      toolong += "ü";
    }
    toolong += ".com";
    EXPECT_EQ(ARES_EBADNAME,
              ares_punycode_encode_domain(toolong.c_str(), &encoded));
    ares_free(encoded);
  }
}

TEST_F(LibraryTest, IDNA) {
  struct {
    ares_status_t status;
    const char   *input;
    const char   *output;
    const char   *descr;
  } tests[] = {
    /* No-op for plain ascii */
    { ARES_SUCCESS,  "www.example.com",   "www.example.com",
      "plain ascii" },
    /* ASCII is lowercased for canonical form */
    { ARES_SUCCESS,  "WWW.EXAMPLE.COM",   "www.example.com",
      "ascii lowercased" },
    /* Unicode casefolding is applied before punycode (unlike the raw
     * punycode API which preserves case) */
    { ARES_SUCCESS,  "www.München.com",   "www.xn--mnchen-3ya.com",
      "unicode casefold" },
    /* Ignored codepoints are removed: U+00AD SOFT HYPHEN.  Spelled in
     * explicit bytes since the raw codepoint is invisible: an editor
     * silently stripping it would leave this case testing nothing */
    { ARES_SUCCESS,  "exam\xC2\xADple.com", "example.com",
      "soft hyphen ignored" },
    /* Label separator variants map to '.': U+3002 IDEOGRAPHIC FULL STOP */
    { ARES_SUCCESS,  "例。com",       "xn--fsq.com",
      "ideographic full stop" },
    /* Deviation characters are valid in nontransitional processing */
    { ARES_SUCCESS,  "faß.de",            "xn--fa-hia.de",
      "sharp s deviation" },
    /* Multi-codepoint compatibility mappings must not be truncated:
     * U+2167 ROMAN NUMERAL EIGHT maps to 'viii' (4 codepoints) */
    { ARES_SUCCESS,  "Ⅷ.example.com",     "viii.example.com",
      "roman numeral viii" },
    /* U+2152 VULGAR FRACTION ONE TENTH maps to '1⁄10' (4 codepoints,
     * including non-ascii U+2044 FRACTION SLASH which is disallowed) */
    { ARES_EBADNAME, "⅒.example.com",     NULL,
      "vulgar fraction one tenth" },
    /* Underscore is in widespread DNS use and must pass through even
     * though the IDNA2008 NV8 exclusions would reject it */
    { ARES_SUCCESS,  "_dmarc.bücher.com", "_dmarc.xn--bcher-kva.com",
      "underscore passthrough" },
    /* Disallowed codepoints are rejected: U+FFFD REPLACEMENT CHARACTER */
    { ARES_EBADNAME, "exam�ple.com", NULL,
      "replacement char disallowed" },
    /* Emoji are excluded by IDNA2008 (NV8).  U+1F600 is spelled in explicit
     * UTF-8 bytes: MSVC without /utf-8 mangles \U escapes beyond the
     * Windows-1252 execution charset into '?' */
    { ARES_EBADNAME, "\xF0\x9F\x98\x80.com", NULL,
      "emoji disallowed" },
    /* An already-encoded label is ASCII and passes through unmodified, no
     * double-encoding */
    { ARES_SUCCESS,  "xn--bcher-kva.de",  "xn--bcher-kva.de",
      "already encoded passthrough" },
    /* Fullwidth characters map to their ASCII equivalents, lowercased:
     * U+FF21..U+FF23 FULLWIDTH LATIN CAPITAL LETTER A..C */
    { ARES_SUCCESS,  "ＡＢＣ.com",         "abc.com",
      "fullwidth mapped to ascii" },
    /* ZWNJ (U+200C) is a deviation codepoint kept by nontransitional
     * processing; CheckJoiners (ContextJ) is documented as not implemented
     * so it is accepted context-free */
    { ARES_SUCCESS,  "a\xE2\x80\x8C" "b.com", "xn--ab-j1t.com",
      "zwnj nontransitional" },
    /* Blank labels pass through for downstream validation to see */
    { ARES_SUCCESS,  "bücher..de",        "xn--bcher-kva..de",
      "empty interior label preserved" },
    { ARES_SUCCESS,  ".",                 ".",
      "root dot" },
    /* A label reduced to nothing by ignored codepoints (here U+00AD SOFT
     * HYPHEN, in explicit bytes) can never form a valid DNS label and is
     * rejected -- unlike the blank labels present in the input above */
    { ARES_EBADNAME, "a.\xC2\xAD.b",      NULL,
      "label of only ignored codepoints" },
    { ARES_EBADNAME, "\xC2\xAD",          NULL,
      "domain of only ignored codepoints" },
    { ARES_SUCCESS,  NULL, NULL, NULL }
  };
  size_t i;

  for (i=0; tests[i].input != NULL; i++) {
    ares_status_t status;
    char         *encoded = NULL;

    if (verbose) std::cerr << "Testing " << tests[i].descr << std::endl;
    status = ares_idna_encode_domain(tests[i].input, &encoded);
    EXPECT_EQ(tests[i].status, status) << tests[i].descr;
    if (status == ARES_SUCCESS && tests[i].output != NULL) {
      EXPECT_STREQ(tests[i].output, encoded) << tests[i].descr;
    }
    ares_free(encoded);
  }

  /* Empty domain trivially round-trips */
  {
    char *out = NULL;
    EXPECT_EQ(ARES_SUCCESS, ares_idna_encode_domain("", &out));
    EXPECT_STREQ("", out);
    ares_free(out);
  }

  EXPECT_NE(ARES_SUCCESS, ares_idna_encode_domain(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_idna_encode_domain("www.bücher.com", NULL));
}

TEST_F(LibraryTest, IDNAAllocFail) {
  int ii;

  /* Every allocation point in the idna/punycode path must fail cleanly with
   * ARES_ENOMEM (ASAN/LSAN CI verifies no leak at any failure point) */
  for (ii = 1; ii <= 30; ii++) {
    char         *out = NULL;
    ares_status_t status;

    ClearFails();
    SetAllocFail(ii);
    status = ares_idna_encode_domain("bücher.München.example", &out);
    if (status == ARES_SUCCESS) {
      EXPECT_STREQ("xn--bcher-kva.xn--mnchen-3ya.example", out);
    } else {
      EXPECT_EQ(ARES_ENOMEM, status) << "attempt " << ii;
    }
    ares_free(out);
  }
}

/* Structural validation of the generated UTS #46 mapping table.  The
 * generator constructs pool references so they are in bounds by design;
 * this catches any regeneration drift or hand-editing before it can reach
 * the runtime lookup */
TEST_F(LibraryTest, IDNAMapTable) {
  size_t i;

  EXPECT_GT(ares_idnamap_data_len, (size_t)0);
  EXPECT_GT(ares_idnamap_data_pool_len, (size_t)0);

  for (i = 0; i < ares_idnamap_data_len; i++) {
    const ares_idnamap_data_t *e = &ares_idnamap_data[i];

    /* Well-formed range, within unicode, sorted and non-overlapping */
    EXPECT_LE(e->code_min, e->code_max) << "entry " << i;
    EXPECT_LE(e->code_max, (unsigned int)0x10FFFF) << "entry " << i;
    if (i > 0) {
      EXPECT_GT(e->code_min, ares_idnamap_data[i - 1].code_max)
        << "entry " << i;
    }

    switch (e->status) {
      case ARES_IDNAMAP_STATUS_MAPPED:
        /* Pool reference must be in bounds and decode as valid UTF-8 */
        EXPECT_GT((unsigned int)e->map_len, (unsigned int)0) << "entry " << i;
        ASSERT_LE((size_t)e->map_offset + e->map_len,
                  ares_idnamap_data_pool_len)
          << "entry " << i;
        {
          ares_buf_t  *buf = ares_buf_create_const(
            &ares_idnamap_data_pool[e->map_offset], e->map_len);
          unsigned int cp = 0;

          ASSERT_NE(nullptr, buf);
          while (ares_buf_len(buf) > 0) {
            EXPECT_EQ(ARES_SUCCESS, ares_buf_fetch_codepoint(buf, &cp))
              << "entry " << i;
            if (HasFailure()) {
              break;
            }
          }
          ares_buf_destroy(buf);
        }
        break;
      case ARES_IDNAMAP_STATUS_DISALLOWED:
      case ARES_IDNAMAP_STATUS_IGNORED:
        EXPECT_EQ(0, e->map_len) << "entry " << i;
        EXPECT_EQ((unsigned int)0, e->map_offset) << "entry " << i;
        break;
      default:
        ADD_FAILURE() << "entry " << i << " has invalid status "
                      << (int)e->status;
        break;
    }
  }
}

TEST_F(LibraryTest, SysConfigDomainsIDNA) {
  ares_sysconfig_t sysconfig;
  memset(&sysconfig, 0, sizeof(sysconfig));

  /* Mixed list: ascii stays untouched, unicode is converted to punycode,
   * and an unconvertible entry (disallowed emoji) is dropped without
   * affecting the rest */
  sysconfig.domains = ares_strsplit(
    "first.com bücher.de \xF0\x9F\x98\x80.com münchen.example", " ",
    &sysconfig.ndomains);
  ASSERT_NE(nullptr, sysconfig.domains);
  ASSERT_EQ((size_t)4, sysconfig.ndomains);

  EXPECT_EQ(ARES_SUCCESS, ares_sysconfig_domains_idna(&sysconfig));
  ASSERT_EQ((size_t)3, sysconfig.ndomains);
  EXPECT_STREQ("first.com", sysconfig.domains[0]);
  EXPECT_STREQ("xn--bcher-kva.de", sysconfig.domains[1]);
  EXPECT_STREQ("xn--mnchen-3ya.example", sysconfig.domains[2]);

  ares_strsplit_free(sysconfig.domains, sysconfig.ndomains);

  /* Unconvertible entries are dropped regardless of position (first and
   * last here, middle above) */
  memset(&sysconfig, 0, sizeof(sysconfig));
  sysconfig.domains = ares_strsplit(
    "\xF0\x9F\x98\x80.com first.com bücher.de \xF0\x9F\x98\x80.org", " ",
    &sysconfig.ndomains);
  ASSERT_NE(nullptr, sysconfig.domains);
  ASSERT_EQ((size_t)4, sysconfig.ndomains);

  EXPECT_EQ(ARES_SUCCESS, ares_sysconfig_domains_idna(&sysconfig));
  ASSERT_EQ((size_t)2, sysconfig.ndomains);
  EXPECT_STREQ("first.com", sysconfig.domains[0]);
  EXPECT_STREQ("xn--bcher-kva.de", sysconfig.domains[1]);

  ares_strsplit_free(sysconfig.domains, sysconfig.ndomains);

  /* If every entry is unconvertible the array itself must be released,
   * otherwise ares_sysconfig_apply() would fail on the empty list and skip
   * applying the rest of the configuration */
  memset(&sysconfig, 0, sizeof(sysconfig));
  sysconfig.domains =
    ares_strsplit("\xF0\x9F\x98\x80.com \xF0\x9F\x98\x80.de", " ",
                  &sysconfig.ndomains);
  ASSERT_NE(nullptr, sysconfig.domains);
  ASSERT_EQ((size_t)2, sysconfig.ndomains);

  EXPECT_EQ(ARES_SUCCESS, ares_sysconfig_domains_idna(&sysconfig));
  EXPECT_EQ((size_t)0, sysconfig.ndomains);
  EXPECT_EQ(nullptr, sysconfig.domains);

  /* Empty list is a no-op */
  memset(&sysconfig, 0, sizeof(sysconfig));
  EXPECT_EQ(ARES_SUCCESS, ares_sysconfig_domains_idna(&sysconfig));
  EXPECT_EQ((size_t)0, sysconfig.ndomains);

  /* An entry unprintable due to an embedded control byte rather than
   * unicode is unchanged by IDNA encoding (ASCII passes through) and is
   * dropped as unusable.  Built by hand: ares_strsplit() itself rejects
   * control bytes, but not every config source goes through it */
  memset(&sysconfig, 0, sizeof(sysconfig));
  sysconfig.domains =
    (char **)ares_malloc_zero(sizeof(*sysconfig.domains) * 2);
  ASSERT_NE(nullptr, sysconfig.domains);
  sysconfig.domains[0] = ares_strdup("f\x01oo.example.com");
  sysconfig.domains[1] = ares_strdup("first.com");
  ASSERT_NE(nullptr, sysconfig.domains[0]);
  ASSERT_NE(nullptr, sysconfig.domains[1]);
  sysconfig.ndomains = 2;

  EXPECT_EQ(ARES_SUCCESS, ares_sysconfig_domains_idna(&sysconfig));
  ASSERT_EQ((size_t)1, sysconfig.ndomains);
  EXPECT_STREQ("first.com", sysconfig.domains[0]);

  ares_strsplit_free(sysconfig.domains, sysconfig.ndomains);

  /* Full resolv.conf line parse path: unicode search values survive line
   * parsing and are converted by the idna pass */
  {
    ares_channel_t *channel = nullptr;
    std::string     line    = "search bücher.de first.com";
    ares_buf_t     *buf     = ares_buf_create_const(
      (const unsigned char *)line.c_str(), line.size());

    ASSERT_NE(nullptr, buf);
    EXPECT_EQ(ARES_SUCCESS, ares_init(&channel));

    memset(&sysconfig, 0, sizeof(sysconfig));
    EXPECT_EQ(ARES_SUCCESS,
              ares_sysconfig_parse_resolv_line(channel, &sysconfig, buf));
    ASSERT_EQ((size_t)2, sysconfig.ndomains);
    EXPECT_STREQ("bücher.de", sysconfig.domains[0]);
    EXPECT_STREQ("first.com", sysconfig.domains[1]);

    EXPECT_EQ(ARES_SUCCESS, ares_sysconfig_domains_idna(&sysconfig));
    ASSERT_EQ((size_t)2, sysconfig.ndomains);
    EXPECT_STREQ("xn--bcher-kva.de", sysconfig.domains[0]);
    EXPECT_STREQ("first.com", sysconfig.domains[1]);

    ares_strsplit_free(sysconfig.domains, sysconfig.ndomains);
    ares_buf_destroy(buf);
    ares_destroy(channel);
  }
}

TEST_F(LibraryTest, SysConfigResolvInlineComments)
{
  const char resolvconf[] = "nameserver 1.2.3.4 # managed nameserver\n"
                            "nameserver 2.3.4.5 ; managed nameserver\n"
                            "search first.com second.com # ignored.example\n"
                            "lookup bind ; file\n"
                            "options ndots:5 ; ndots:9\n";
  ares_sysconfig_t sysconfig;
  ares_channel_t  *channel = nullptr;
  ares_buf_t      *buf;

  memset(&sysconfig, 0, sizeof(sysconfig));
  buf = ares_buf_create_const((const unsigned char *)resolvconf,
                              sizeof(resolvconf) - 1);
  ASSERT_NE(nullptr, buf);
  ASSERT_EQ(ARES_SUCCESS, ares_init(&channel));

  EXPECT_EQ(ARES_SUCCESS,
            ares_sysconfig_process_buf(channel, &sysconfig, buf,
                                       ares_sysconfig_parse_resolv_line));
  EXPECT_EQ((size_t)2, ares_llist_len(sysconfig.sconfig));
  ASSERT_EQ((size_t)2, sysconfig.ndomains);
  EXPECT_STREQ("first.com", sysconfig.domains[0]);
  EXPECT_STREQ("second.com", sysconfig.domains[1]);
  EXPECT_STREQ("b", sysconfig.lookups);
  EXPECT_EQ((size_t)5, sysconfig.ndots);

  ares_llist_destroy(sysconfig.sconfig);
  ares_strsplit_free(sysconfig.domains, sysconfig.ndomains);
  ares_free(sysconfig.sortlist);
  ares_free(sysconfig.lookups);
  ares_buf_destroy(buf);
  ares_destroy(channel);
}

TEST_F(LibraryTest, BufCharset) {
  struct {
    ares_bool_t ascii_ok;
    ares_bool_t utf8_ok;
    const char *data;
    const char *descr;
  } tests[] = {
    { ARES_TRUE,  ARES_TRUE,  "plain ascii",         "printable ascii"     },
    { ARES_FALSE, ARES_TRUE,  "b\xC3\xBC" "cher",    "2-byte utf8"         },
    { ARES_FALSE, ARES_TRUE,  "b\xE4\xBE\x8B",       "3-byte utf8"         },
    { ARES_FALSE, ARES_TRUE,  "b\xF0\x9F\x98\x80",   "4-byte utf8"         },
    { ARES_FALSE, ARES_FALSE, "b\xC3",               "truncated sequence"  },
    { ARES_FALSE, ARES_FALSE, "b\xC3\x28",           "bad continuation"    },
    { ARES_FALSE, ARES_FALSE, "b\xC0\xAF",           "overlong encoding"   },
    { ARES_FALSE, ARES_FALSE, "b\xED\xA0\x80",       "surrogate half"      },
    { ARES_FALSE, ARES_FALSE, "b\xFF",               "invalid lead byte"   },
    { ARES_FALSE, ARES_FALSE, "b\x01",               "non-printable ascii" },
    { ARES_FALSE, ARES_FALSE, "b\x7F",               "ascii del"           },
    { ARES_FALSE, ARES_FALSE, NULL, NULL }
  };
  size_t i;
  size_t c;

  for (i = 0; tests[i].data != NULL; i++) {
    for (c = 0; c < 2; c++) {
      ares_buf_charset_t charset =
        (c == 0) ? ARES_BUF_CHARSET_ASCII : ARES_BUF_CHARSET_UTF8;
      ares_bool_t   expect_ok = (c == 0) ? tests[i].ascii_ok : tests[i].utf8_ok;
      size_t        data_len  = strlen(tests[i].data);
      ares_buf_t   *buf;
      char          strbuf[64];
      char         *str = NULL;
      ares_status_t status;

      if (verbose) std::cerr << "Testing " << tests[i].descr
                             << " charset " << (int)charset << std::endl;

      /* ares_buf_fetch_str_dup() */
      buf = ares_buf_create_const((const unsigned char *)tests[i].data,
                                  data_len);
      ASSERT_NE(nullptr, buf);
      status = ares_buf_fetch_str_dup(buf, data_len, &str, charset);
      EXPECT_EQ(expect_ok ? ARES_TRUE : ARES_FALSE,
                (status == ARES_SUCCESS) ? ARES_TRUE : ARES_FALSE)
        << tests[i].descr << " fetch_str_dup charset " << (int)charset;
      if (status == ARES_SUCCESS) {
        EXPECT_STREQ(tests[i].data, str);
      } else {
        EXPECT_EQ(ARES_EBADSTR, status)
          << tests[i].descr << " fetch_str_dup charset " << (int)charset;
      }
      ares_free(str);
      str = NULL;
      ares_buf_destroy(buf);

      /* ares_buf_tag_fetch_string() and ares_buf_tag_fetch_strdup() */
      buf = ares_buf_create_const((const unsigned char *)tests[i].data,
                                  data_len);
      ASSERT_NE(nullptr, buf);
      ares_buf_tag(buf);
      ares_buf_consume(buf, data_len);

      status = ares_buf_tag_fetch_string(buf, strbuf, sizeof(strbuf), charset);
      EXPECT_EQ(expect_ok ? ARES_TRUE : ARES_FALSE,
                (status == ARES_SUCCESS) ? ARES_TRUE : ARES_FALSE)
        << tests[i].descr << " tag_fetch_string charset " << (int)charset;
      if (status == ARES_SUCCESS) {
        EXPECT_STREQ(tests[i].data, strbuf);
      } else {
        EXPECT_EQ(ARES_EBADSTR, status)
          << tests[i].descr << " tag_fetch_string charset " << (int)charset;
      }

      status = ares_buf_tag_fetch_strdup(buf, &str, charset);
      EXPECT_EQ(expect_ok ? ARES_TRUE : ARES_FALSE,
                (status == ARES_SUCCESS) ? ARES_TRUE : ARES_FALSE)
        << tests[i].descr << " tag_fetch_strdup charset " << (int)charset;
      if (status == ARES_SUCCESS) {
        EXPECT_STREQ(tests[i].data, str);
      } else {
        EXPECT_EQ(ARES_EBADSTR, status)
          << tests[i].descr << " tag_fetch_strdup charset " << (int)charset;
      }
      ares_free(str);
      str = NULL;
      ares_buf_destroy(buf);
    }
  }
}

TEST_F(LibraryTest, BufCodepoint) {
  /* Encode boundaries for each UTF-8 sequence length, plus invalid scalar
   * values, verified byte-exact and round-tripped through the decoder */
  struct {
    unsigned int cp;
    const char  *utf8; /* NULL = not a valid scalar value, must be rejected */
  } tests[] = {
    { 0x41,     "A"                },
    { 0x7F,     "\x7F"             },
    { 0x80,     "\xC2\x80"         },
    { 0x7FF,    "\xDF\xBF"         },
    { 0x800,    "\xE0\xA0\x80"     },
    { 0xD7FF,   "\xED\x9F\xBF"     },
    { 0xE000,   "\xEE\x80\x80"     },
    { 0xFFFF,   "\xEF\xBF\xBF"     },
    { 0x10000,  "\xF0\x90\x80\x80" },
    { 0x10FFFF, "\xF4\x8F\xBF\xBF" },
    { 0xD800,   NULL               },
    { 0xDFFF,   NULL               },
    { 0x110000, NULL               },
  };
  size_t i;

  for (i = 0; i < sizeof(tests) / sizeof(*tests); i++) {
    ares_buf_t   *buf = ares_buf_create();
    ares_status_t status;
    char         *str = NULL;
    size_t        len = 0;

    ASSERT_NE(nullptr, buf);
    status = ares_buf_append_codepoint(buf, tests[i].cp);

    if (tests[i].utf8 == NULL) {
      EXPECT_EQ(ARES_EBADSTR, status) << "codepoint 0x" << std::hex
                                      << tests[i].cp;
      ares_buf_destroy(buf);
      continue;
    }

    ASSERT_EQ(ARES_SUCCESS, status) << "codepoint 0x" << std::hex
                                    << tests[i].cp;

    str = ares_buf_finish_str(buf, &len);
    buf = NULL;
    ASSERT_NE(nullptr, str);
    EXPECT_EQ(strlen(tests[i].utf8), len);
    EXPECT_STREQ(tests[i].utf8, str);

    /* Round-trip through the decoder */
    {
      ares_buf_t  *rbuf = ares_buf_create_const((const unsigned char *)str,
                                                len);
      unsigned int cp   = 0;

      ASSERT_NE(nullptr, rbuf);
      EXPECT_EQ(ARES_SUCCESS, ares_buf_fetch_codepoint(rbuf, &cp));
      EXPECT_EQ(tests[i].cp, cp);
      EXPECT_EQ((size_t)0, ares_buf_len(rbuf));
      ares_buf_destroy(rbuf);
    }
    ares_free(str);
  }

  /* ares_buf_len_utf8() counts codepoints, not bytes */
  {
    const char *data = "a\xC3\xBC\xE4\xBE\x8B\xF0\x9F\x98\x80"; /* aü例😀 */
    ares_buf_t *buf  = ares_buf_create_const((const unsigned char *)data,
                                             strlen(data));
    size_t      cnt  = 0;

    ASSERT_NE(nullptr, buf);
    EXPECT_EQ(ARES_SUCCESS, ares_buf_len_utf8(buf, &cnt));
    EXPECT_EQ((size_t)4, cnt);
    ares_buf_destroy(buf);
  }

  /* ares_buf_consume_last_charset() semantics */
  {
    ares_buf_t *buf =
      ares_buf_create_const((const unsigned char *)"abc-def", 7);
    size_t      n;

    ASSERT_NE(nullptr, buf);
    /* Found: consumes up to (not including) the last matching character */
    n = ares_buf_consume_last_charset(buf, (const unsigned char *)"-", 1,
                                      ARES_TRUE);
    EXPECT_EQ((size_t)3, n);
    EXPECT_EQ((size_t)4, ares_buf_len(buf)); /* "-def" remains */
    /* Not found, required: SIZE_MAX and nothing is consumed */
    n = ares_buf_consume_last_charset(buf, (const unsigned char *)"@", 1,
                                      ARES_TRUE);
    EXPECT_EQ(SIZE_MAX, n);
    EXPECT_EQ((size_t)4, ares_buf_len(buf));
    /* Not found, not required: consumes the remainder */
    n = ares_buf_consume_last_charset(buf, (const unsigned char *)"@", 1,
                                      ARES_FALSE);
    EXPECT_EQ((size_t)4, n);
    EXPECT_EQ((size_t)0, ares_buf_len(buf));
    /* Empty buffer: SIZE_MAX when required, 0 otherwise */
    n = ares_buf_consume_last_charset(buf, (const unsigned char *)"@", 1,
                                      ARES_TRUE);
    EXPECT_EQ(SIZE_MAX, n);
    n = ares_buf_consume_last_charset(buf, (const unsigned char *)"@", 1,
                                      ARES_FALSE);
    EXPECT_EQ((size_t)0, n);
    ares_buf_destroy(buf);
  }

  /* ares_buf_isprint() */
  {
    ares_buf_t *buf = ares_buf_create_const((const unsigned char *)"abc", 3);
    ASSERT_NE(nullptr, buf);
    EXPECT_EQ(ARES_TRUE, ares_buf_isprint(buf));
    ares_buf_destroy(buf);
    buf = ares_buf_create_const((const unsigned char *)"a\x01" "c", 3);
    ASSERT_NE(nullptr, buf);
    EXPECT_EQ(ARES_FALSE, ares_buf_isprint(buf));
    ares_buf_destroy(buf);
  }

  /* ARES_BUF_SPLIT_UTF8 (via ares_strsplit): a single invalid element fails
   * the entire split rather than dropping only that element, in contrast to
   * the drop-individually semantics of the sysconfig IDNA pass */
  {
    size_t n   = 0;
    char **out = ares_strsplit("good.com b\xFF" "ad.com", " ", &n);
    EXPECT_EQ(nullptr, out);
    out = ares_strsplit("good.com bücher.de", " ", &n);
    ASSERT_NE(nullptr, out);
    EXPECT_EQ((size_t)2, n);
    EXPECT_STREQ("good.com", out[0]);
    EXPECT_STREQ("bücher.de", out[1]);
    ares_strsplit_free(out, n);
  }
}

// The cache key must distinguish requests whose answers are not
// interchangeable.  Two shapes are easy to get wrong because names reach the
// key unescaped: a request with two questions versus one whose name spells out
// the second, and two requests with the same question count whose names can be
// made to run together.  Both are narrow to reach -- they need a hand-built
// record with more than one question, which real servers reject -- but the key
// asserts they are distinct, so pin it.
TEST_F(LibraryTest, QcacheKeyDistinguishesQuestions) {
  struct qcase {
    const char *n1;
    const char *n2; /* nullptr for a single-question record */
  };
  const qcase cases[] = {
    { "one.example.net",                      "two.example.net"                        },
    { "one.example.net|A|IN|two.example.net", nullptr                                  },
    { "one.example.net",                      "two.example.net|A|IN|three.example.net" },
    { "one.example.net|A|IN|two.example.net", "three.example.net"                      },
  };
  std::vector<std::string> keys;

  for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
    ares_dns_record_t *req = nullptr;
    char              *key = nullptr;

    EXPECT_EQ(ARES_SUCCESS,
              ares_dns_record_create(&req, 0, ARES_FLAG_RD, ARES_OPCODE_QUERY,
                                     ARES_RCODE_NOERROR));
    EXPECT_EQ(ARES_SUCCESS,
              ares_dns_record_query_add(req, cases[i].n1, ARES_REC_TYPE_A,
                                        ARES_CLASS_IN));
    if (cases[i].n2 != nullptr) {
      EXPECT_EQ(ARES_SUCCESS,
                ares_dns_record_query_add(req, cases[i].n2, ARES_REC_TYPE_A,
                                          ARES_CLASS_IN));
    }

    key = ares_qcache_calc_key(req);
    ASSERT_NE(nullptr, key);
    keys.push_back(std::string(key));
    ares_free_string(key);
    ares_dns_record_destroy(req);
  }

  /* Every one of these is a different request, so every key must differ. */
  for (size_t i = 0; i < keys.size(); i++) {
    for (size_t j = i + 1; j < keys.size(); j++) {
      EXPECT_NE(keys[i], keys[j])
        << "cache key collision between case " << i << " and case " << j
        << ": " << keys[i];
    }
  }
}

#endif /* !CARES_SYMBOL_HIDING */

TEST_F(LibraryTest, InetPtoN) {
  struct in_addr a4;
  struct in6_addr a6;
  EXPECT_EQ(1, ares_inet_pton(AF_INET, "1.2.3.4", &a4));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ff", &a6));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "12:34::ffff:1.2.3.4", &a6));
  EXPECT_EQ(0, ares_inet_pton(AF_INET, "xyzzy", &a4));
  // Too many octets is unparsable input, not a system error.
  EXPECT_EQ(0, ares_inet_pton(AF_INET, "1.2.3.4.5", &a4));
  EXPECT_EQ(0, ares_inet_pton(AF_INET, "0x0102030405", &a4));
  EXPECT_EQ(-1, ares_inet_pton(AF_INET+AF_INET6, "1.2.3.4", &a4));
}

// ares_inet_pton() parses addresses, not networks: like inet_pton(3) it must
// reject a "/bits" prefix length.  It used to accept one and, for IPv6, write
// only (bits+7)/8 bytes of dst while still returning 1.
TEST_F(LibraryTest, InetPtoNRejectsPrefixLength) {
  const char *cases6[] = { "::1/0", "ffff::1/16", "2001:db8::1/64",
                           "2001:db8::1/128", "::ffff:1.2.3.4/8",
                           "::ffff:1.2.3.4/32" };
  const char *cases4[] = { "1.2.3.4/8", "1.2.3.4/0", "1.2.3.4/32", "10/8",
                           "0x0a000000/8" };
  unsigned char a4[4];
  unsigned char a6[16];
  size_t        i;

  for (i = 0; i < sizeof(cases6) / sizeof(*cases6); i++) {
    EXPECT_EQ(0, ares_inet_pton(AF_INET6, cases6[i], a6)) << cases6[i];
  }
  for (i = 0; i < sizeof(cases4) / sizeof(*cases4); i++) {
    EXPECT_EQ(0, ares_inet_pton(AF_INET, cases4[i], a4)) << cases4[i];
  }

  // Without a prefix length, the whole destination is written.
  memset(a6, 0x41, sizeof(a6));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "ffff::1", a6));
  EXPECT_EQ("ffff:0000:0000:0000:0000:0000:0000:0001",
            AddressToString(a6, 16));
  memset(a6, 0x41, sizeof(a6));
  EXPECT_EQ(1, ares_inet_pton(AF_INET6, "::ffff:1.2.3.4", a6));
  EXPECT_EQ("0000:0000:0000:0000:0000:ffff:0102:0304",
            AddressToString(a6, 16));
  memset(a4, 0x41, sizeof(a4));
  EXPECT_EQ(1, ares_inet_pton(AF_INET, "1.2.3.4", a4));
  EXPECT_EQ("1.2.3.4", AddressToString(a4, 4));
}

TEST_F(LibraryTest, FreeCorruptData) {
  // ares_free_data(p) expects that there is a type field and a marker
  // field in the memory before p.  Feed it incorrect versions of each.
  struct ares_data *data = (struct ares_data *)malloc(sizeof(struct ares_data));
  void* p = &(data->data);

  // Invalid type
  data->type = (ares_datatype)ARES_DATATYPE_LAST;
  data->mark = ARES_DATATYPE_MARK;
  ares_free_data(p);

  // Invalid marker
  data->type = (ares_datatype)ARES_DATATYPE_MX_REPLY;
  data->mark = ARES_DATATYPE_MARK + 1;
  ares_free_data(p);

  // Null pointer
  ares_free_data(nullptr);

  free(data);
}

TEST(LibraryInit, StrdupFailures) {
  EXPECT_EQ(ARES_SUCCESS, ares_library_init(ARES_LIB_INIT_ALL));
  char* copy = ares_strdup("string");
  EXPECT_NE(nullptr, copy);
  ares_free(copy);
  ares_library_cleanup();
}

TEST_F(LibraryTest, StrdupFailures) {
  SetAllocFail(1);
  char* copy = ares_strdup("string");
  EXPECT_EQ(nullptr, copy);
}

#ifndef WIN32
TEST_F(FileChannelTest, GetAddrInfoHostsReplacedWithOlderMtime)
{
  TempFile                   hostsfile("1.2.3.4 example.com");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };
  hints.ai_family                  = AF_INET;
  hints.ai_flags                   = ARES_AI_ENVHOSTS | ARES_AI_NOSORT;

  AddrInfoResult result1 = {};
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback,
                   &result1);
  Process();
  EXPECT_TRUE(result1.done_);
  {
    std::stringstream ss;
    ss << result1.ai_;
    EXPECT_EQ("{addr=[1.2.3.4]}", ss.str());
  }

  /* Replace the file with new content but an OLDER mtime, as produced by
   * tar -x, cp -p, package downgrades or backup restores. */
  {
    FILE          *fp = fopen(hostsfile.filename(), "w");
    struct timeval times[2];
    ASSERT_NE(nullptr, fp);
    fprintf(fp, "9.9.9.9 example.com");
    fclose(fp);
    gettimeofday(&times[0], NULL);
    times[0].tv_sec -= 3600;
    times[1]         = times[0];
    ASSERT_EQ(0, utimes(hostsfile.filename(), times));
  }

  AddrInfoResult result2 = {};
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback,
                   &result2);
  Process();
  EXPECT_TRUE(result2.done_);
  std::stringstream ss;
  ss << result2.ai_;
  EXPECT_EQ("{addr=[9.9.9.9]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsReplacedWithSameMtime)
{
  TempFile                   hostsfile("1.2.3.4 example.com");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };
  hints.ai_family                  = AF_INET;
  hints.ai_flags                   = ARES_AI_ENVHOSTS | ARES_AI_NOSORT;

  /* Pin the mtime a couple of seconds in the past BEFORE the first lookup,
   * so the parse observes that mtime while the same-second re-parse
   * heuristic (parse time vs mtime) sees a fresh file and stays out of the
   * way. */
  struct timeval pinned[2];
  gettimeofday(&pinned[0], NULL);
  pinned[0].tv_sec -= 2;
  pinned[1]         = pinned[0];
  ASSERT_EQ(0, utimes(hostsfile.filename(), pinned));

  AddrInfoResult result1 = {};
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback,
                   &result1);
  Process();
  EXPECT_TRUE(result1.done_);
  {
    std::stringstream ss;
    ss << result1.ai_;
    EXPECT_EQ("{addr=[1.2.3.4]}", ss.str());
  }

  /* Replace the file with new content of a different length but the SAME
   * mtime, as produced by builds that normalize file times: on NixOS,
   * /etc/hosts is a symlink into the package store where every file
   * carries the same mtime, so pointing the symlink at a new store path
   * changes nothing an mtime-only check can see.  The mtime is pinned
   * back to the exact value the cache observed, so only the size/inode
   * identity can catch the replacement. */
  {
    FILE *fp = fopen(hostsfile.filename(), "w");
    ASSERT_NE(nullptr, fp);
    fprintf(fp, "10.11.12.13 example.com");
    fclose(fp);
    ASSERT_EQ(0, utimes(hostsfile.filename(), pinned));
  }

  AddrInfoResult result2 = {};
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback,
                   &result2);
  Process();
  EXPECT_TRUE(result2.done_);
  std::stringstream ss;
  ss << result2.ai_;
  EXPECT_EQ("{addr=[10.11.12.13]}", ss.str());

  /* Swap in a different file of the same length and the same mtime, as a
   * symlink retarget or atomic rename does, so only the inode differs. */
  {
    std::string newfile = std::string(hostsfile.filename()) + ".new";
    FILE       *fp      = fopen(newfile.c_str(), "w");
    ASSERT_NE(nullptr, fp);
    fprintf(fp, "10.11.12.14 example.com");
    fclose(fp);
    ASSERT_EQ(0, utimes(newfile.c_str(), pinned));
    ASSERT_EQ(0, rename(newfile.c_str(), hostsfile.filename()));
  }

  AddrInfoResult result3 = {};
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback,
                   &result3);
  Process();
  EXPECT_TRUE(result3.done_);
  std::stringstream ss3;
  ss3 << result3.ai_;
  EXPECT_EQ("{addr=[10.11.12.14]}", ss3.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsEmptiedInPlace)
{
  TempFile                   hostsfile("1.2.3.4 example.com");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };
  hints.ai_family                  = AF_INET;
  hints.ai_flags                   = ARES_AI_ENVHOSTS | ARES_AI_NOSORT;

  /* Pin the mtime a couple of seconds in the past before the first lookup,
   * so the same-second re-parse heuristic stays out of the way, then empty
   * the file in place and put the mtime back: only the size can catch it,
   * and a size of zero must still count as a real value. */
  struct timeval pinned[2];
  gettimeofday(&pinned[0], NULL);
  pinned[0].tv_sec -= 2;
  pinned[1]         = pinned[0];
  ASSERT_EQ(0, utimes(hostsfile.filename(), pinned));

  AddrInfoResult result1 = {};
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback,
                   &result1);
  Process();
  EXPECT_TRUE(result1.done_);
  {
    std::stringstream ss;
    ss << result1.ai_;
    EXPECT_EQ("{addr=[1.2.3.4]}", ss.str());
  }

  {
    FILE *fp = fopen(hostsfile.filename(), "w");
    ASSERT_NE(nullptr, fp);
    fclose(fp);
    ASSERT_EQ(0, utimes(hostsfile.filename(), pinned));
  }

  AddrInfoResult result2 = {};
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback,
                   &result2);
  Process();
  EXPECT_TRUE(result2.done_);
  /* The channel is files only and the emptied hosts file no longer holds the
   * name, so the lookup must fail instead of answering the stale address. */
  EXPECT_NE(ARES_SUCCESS, result2.status_);
}
#endif

TEST_F(FileChannelTest, GetAddrInfoHostsPositive) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{example.com addr=[1.2.3.4]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsSpaces) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "google.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{www.google.com->google.com, www2.google.com->google.com addr=[2.3.4.5]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsByALias) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "www2.google.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{www.google.com->google.com, www2.google.com->google.com addr=[2.3.4.5]}", ss.str());
}

TEST_F(FileChannelTest, GetAddrInfoHostsIPV6) {
  TempFile hostsfile("1.2.3.4 example.com  \n"
                     "  2.3.4.5\tgoogle.com   www.google.com\twww2.google.com\n"
                     "#comment\n"
                     "4.5.6.7\n"
                     "1.3.5.7  \n"
                     "::1    ipv6.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints = {0, 0, 0, 0};
  AddrInfoResult result = {};
  hints.ai_family = AF_INET6;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "ipv6.com", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{ipv6.com addr=[[0000:0000:0000:0000:0000:0000:0000:0001]]}", ss.str());
}

// Regression for #1049: hostnames merged into a single entry only because they
// share an ip address must not leak each other's *other* addresses (forward
// lookup) or appear as each other's aliases (address-scoped cnames).  Here
// mullvad-no-svg shares 10.124.2.38 with mullvad-no (which drags in the whole
// group), but must resolve to only 10.124.2.38, and mullvad-no-osl (no shared
// address) must not be reported as an alias.
TEST_F(FileChannelTest, GetAddrInfoHostsSharedIPNoLeak)
{
  TempFile                   hostsfile("10.124.0.6   mullvad-no\n"
                                       "10.124.0.108 mullvad-no\n"
                                       "10.124.2.38  mullvad-no\n"
                                       "10.124.0.6   mullvad-no-osl\n"
                                       "10.124.0.108 mullvad-no-osl\n"
                                       "10.124.2.38  mullvad-no-svg\n");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints  = { 0, 0, 0, 0 };
  AddrInfoResult             result = {};
  hints.ai_family                   = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "mullvad-no-svg", NULL, &hints, AddrInfoCallback,
                   &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{mullvad-no-svg->mullvad-no addr=[10.124.2.38]}", ss.str());
}

// The legitimate multi-address case still returns all of a hostname's own
// addresses (mullvad-no genuinely has three).
TEST_F(FileChannelTest, GetAddrInfoHostsMultiAddressPreserved)
{
  TempFile                   hostsfile("10.124.0.6   mullvad-no\n"
                                       "10.124.0.108 mullvad-no\n"
                                       "10.124.2.38  mullvad-no\n"
                                       "10.124.0.6   mullvad-no-osl\n"
                                       "10.124.0.108 mullvad-no-osl\n"
                                       "10.124.2.38  mullvad-no-svg\n");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints  = { 0, 0, 0, 0 };
  AddrInfoResult             result = {};
  hints.ai_family                   = AF_INET;
  hints.ai_flags                    = ARES_AI_NOSORT | ARES_AI_ENVHOSTS;
  ares_getaddrinfo(channel_, "mullvad-no", NULL, &hints, AddrInfoCallback,
                   &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{addr=[10.124.0.6], addr=[10.124.0.108], addr=[10.124.2.38]}",
            ss.str());
}

// Regression for #1049: a "bridge" line whose ip already belongs to one
// hostname and whose hostname already belongs to another must NOT drop the
// address.  Here mullvad-no-svg appears with 10.124.2.38 and with 10.64.0.1
// (a line that also lists mullvad).  Both addresses must be returned; the old
// merged store silently dropped 10.64.0.1.
TEST_F(FileChannelTest, GetAddrInfoHostsBridgeFallback)
{
  TempFile                   hostsfile("10.64.0.1 mullvad\n"
                                       "10.124.2.38 mullvad-no-svg\n"
                                       "10.64.0.1 mullvad-no-svg\n");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints  = { 0, 0, 0, 0 };
  AddrInfoResult             result = {};
  hints.ai_family                   = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "mullvad-no-svg", NULL, &hints, AddrInfoCallback,
                   &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{mullvad->mullvad-no-svg addr=[10.124.2.38], addr=[10.64.0.1]}",
            ss.str());
}

// A shared ip chains hostnames together, but a forward lookup must return only
// the addresses the queried name actually appeared with.  c shares 1.1.1.1
// with a (which owns only 1.1.1.1) and has its own 3.3.3.3; b's 2.2.2.2 must
// not leak in.
TEST_F(FileChannelTest, GetAddrInfoHostsChain)
{
  TempFile                   hostsfile("1.1.1.1 a\n"
                                       "2.2.2.2 b\n"
                                       "1.1.1.1 c\n"
                                       "3.3.3.3 c\n");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints  = { 0, 0, 0, 0 };
  AddrInfoResult             result = {};
  hints.ai_family                   = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "c", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{c->a addr=[1.1.1.1], addr=[3.3.3.3]}", ss.str());
}

// A hostname sharing an ip with a multi-family host must not inherit the other
// host's address of a different family.  other shares 192.168.1.1 with host,
// but host's 2620:1234::1 must not appear in an AF_UNSPEC lookup of other.
TEST_F(FileChannelTest, GetAddrInfoHostsMixedFamilyNoLeak)
{
  TempFile                   hostsfile("192.168.1.1 host\n"
                                       "2620:1234::1 host\n"
                                       "192.168.1.1 other\n");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints  = { 0, 0, 0, 0 };
  AddrInfoResult             result = {};
  hints.ai_family                   = AF_UNSPEC;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "other", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{other->host addr=[192.168.1.1]}", ss.str());
}

// Hostnames are matched case-insensitively, so FooBar and foobar are the same
// name and FOOBAR resolves to both of their addresses.
TEST_F(FileChannelTest, GetAddrInfoHostsCaseInsensitive)
{
  TempFile                   hostsfile("1.1.1.1 FooBar\n"
                                       "2.2.2.2 foobar\n");
  EnvValue                   with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints  = { 0, 0, 0, 0 };
  AddrInfoResult             result = {};
  hints.ai_family                   = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "FOOBAR", NULL, &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.ai_;
  EXPECT_EQ("{FooBar addr=[1.1.1.1], addr=[2.2.2.2]}", ss.str());
}

// Reverse lookup (ares_gethostbyaddr) is address-scoped: only the names that
// appeared with the queried address, and only that address.  a (which only
// shares 1.1.1.1 with b) must not appear when reverse-resolving 2.2.2.2.
// gethostbyaddr uses use_env=FALSE, so configure the hosts file via
// ARES_OPT_HOSTS_FILE on a private channel.
TEST_F(LibraryTest, GetHostByAddrHostsFile)
{
  TempFile            hostsfile("1.1.1.1 a\n"
                                "1.1.1.1 b\n"
                                "2.2.2.2 b\n"
                                "2.2.2.2 c\n");
  ares_channel_t     *channel = nullptr;
  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  opts.hosts_path = strdup(hostsfile.filename());
  int optmask     = ARES_OPT_HOSTS_FILE;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  free(opts.hosts_path);

  struct in_addr addr;
  ares_inet_pton(AF_INET, "2.2.2.2", &addr);
  HostResult result;
  ares_gethostbyaddr(channel, &addr, sizeof(addr), AF_INET, HostCallback,
                     &result);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'b' aliases=[c] addrs=[2.2.2.2]}", ss.str());

  ares_destroy(channel);
}

// Forward lookup via ares_gethostbyname (also use_env=FALSE, private channel).
// c only appeared with 2.2.2.2; b's other address 1.1.1.1 must not leak.  The
// canonical name is the first file-order name that shares the address (b).
TEST_F(LibraryTest, GetHostByNameHostsFile)
{
  TempFile            hostsfile("1.1.1.1 a\n"
                                "1.1.1.1 b\n"
                                "2.2.2.2 b\n"
                                "2.2.2.2 c\n");
  ares_channel_t     *channel = nullptr;
  struct ares_options opts;
  memset(&opts, 0, sizeof(opts));
  opts.hosts_path = strdup(hostsfile.filename());
  int optmask     = ARES_OPT_HOSTS_FILE;
  EXPECT_EQ(ARES_SUCCESS, ares_init_options(&channel, &opts, optmask));
  free(opts.hosts_path);

  HostResult result;
  ares_gethostbyname(channel, "c", AF_INET, HostCallback, &result);
  ProcessWork(channel, NoExtraFDs, nullptr);
  EXPECT_TRUE(result.done_);
  std::stringstream ss;
  ss << result.host_;
  EXPECT_EQ("{'b' aliases=[c] addrs=[2.2.2.2]}", ss.str());

  ares_destroy(channel);
}

TEST_F(FileChannelTest, GetAddrInfoInvalidService) {
  TempFile hostsfile("1.2.3.4 example.com");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints{};
  AddrInfoResult result{};
  hints.ai_family = AF_INET;
  hints.ai_flags = ARES_AI_CANONNAME | ARES_AI_ENVHOSTS | ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "example.com", "invalid", &hints, AddrInfoCallback, &result);
  Process();
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(result.status_, ARES_ESERVICE);
}

TEST_F(FileChannelTest, GetAddrInfoAllocFail) {
  TempFile hostsfile("1.2.3.4 example.com alias1 alias2\n");
  EnvValue with_env("CARES_HOSTS", hostsfile.filename());
  struct ares_addrinfo_hints hints;

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;

  // Fail a variety of different memory allocations, and confirm
  // that the operation either fails with ENOMEM or succeeds
  // with the expected result.
  const int kCount = 34;
  AddrInfoResult results[kCount];
  for (int ii = 1; ii <= kCount; ii++) {
    AddrInfoResult* result = &(results[ii - 1]);
    ClearFails();
    SetAllocFail(ii);
    ares_getaddrinfo(channel_, "example.com", NULL, &hints, AddrInfoCallback, result);
    Process();
    EXPECT_TRUE(result->done_);
    if (result->status_ == ARES_SUCCESS) {
      std::stringstream ss;
      ss << result->ai_;
      EXPECT_EQ("{alias1->example.com, alias2->example.com addr=[1.2.3.4]}", ss.str()) << " failed alloc #" << ii;
      if (verbose) std::cerr << "Succeeded despite failure of alloc #" << ii << std::endl;
    }
  }
}

TEST_F(LibraryTest, DNSWriteOversizedRdlength)
{
  ares_dns_record_t         *dnsrec = nullptr;
  ares_dns_rr_t             *rr     = nullptr;
  unsigned char             *msg    = nullptr;
  size_t                     msglen = 0;

  // 300 x 255-byte character-strings = rdlength 76500 > 65535.
  std::vector<unsigned char> str(255, 'x');

  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_record_create(&dnsrec, 0x1234, 0, ARES_OPCODE_QUERY,
                                   ARES_RCODE_NOERROR));
  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_record_query_add(dnsrec, "example.com", ARES_REC_TYPE_TXT,
                                      ARES_CLASS_IN));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_record_rr_add(
                            &rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
                            ARES_REC_TYPE_TXT, ARES_CLASS_IN, 3600));
  for (size_t i = 0; i < 300; i++) {
    EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA,
                                                 str.data(), str.size()));
  }

  // rdlength does not fit in 16 bits and must not be silently truncated into
  // a structurally corrupt message reported as ARES_SUCCESS.
  EXPECT_EQ(ARES_EBADQUERY, ares_dns_write(dnsrec, &msg, &msglen));
  EXPECT_EQ(nullptr, msg);
  EXPECT_EQ(0U, msglen);

  ares_dns_record_destroy(dnsrec);
  ares_free_string(msg);
}

TEST_F(LibraryTest, DNSWriteMaximumMessageSize)
{
  ares_dns_record_t *dnsrec   = nullptr;
  ares_dns_record_t *parsed   = nullptr;
  ares_dns_rr_t     *rr       = nullptr;
  unsigned char     *msg      = nullptr;
  size_t             msglen   = 0;
  size_t             overhead = 0;
  size_t             max_data = 0;

  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_record_create(&dnsrec, 0x1234, 0, ARES_OPCODE_QUERY,
                                   ARES_RCODE_NOERROR));
  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_record_query_add(dnsrec, "example.com", ARES_REC_TYPE_A,
                                      ARES_CLASS_IN));
  EXPECT_EQ(ARES_SUCCESS,
            ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "",
                                   ARES_REC_TYPE_RAW_RR, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_u16(rr, ARES_RR_RAW_RR_TYPE, 65432));

  // Measure the fixed framing with a one-byte raw record, so the exact
  // per-byte limit can be hit: the largest message that fits must write and
  // parse back, and a single extra byte must be rejected.
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_bin(
                            rr, ARES_RR_RAW_RR_DATA,
                            reinterpret_cast<const unsigned char *>("x"), 1));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));
  overhead = msglen - 1; /* framing without the data byte */
  ares_free_string(msg);
  msg = nullptr;

  max_data = 65535 - overhead;
  std::vector<unsigned char> data(max_data, 'x');
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_bin(rr, ARES_RR_RAW_RR_DATA,
                                              data.data(), data.size()));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));
  EXPECT_EQ(65535U, msglen);
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, 0, &parsed));
  ares_dns_record_destroy(parsed);
  parsed = nullptr;
  ares_free_string(msg);
  msg = nullptr;

  data.push_back('x');
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_bin(rr, ARES_RR_RAW_RR_DATA,
                                              data.data(), data.size()));
  EXPECT_EQ(ARES_EBADQUERY, ares_dns_write(dnsrec, &msg, &msglen));
  EXPECT_EQ(nullptr, msg);
  EXPECT_EQ(0U, msglen);

  ares_dns_record_destroy(dnsrec);
  ares_free_string(msg);
}

TEST_F(LibraryTest, DNSRecord) {
  ares_dns_record_t   *dnsrec = NULL;
  ares_dns_rr_t       *rr     = NULL;
  struct in_addr       addr;
  struct ares_in6_addr addr6;
  unsigned char       *msg    = NULL;
  size_t               msglen = 0;
  size_t               qdcount = 0;
  size_t               ancount = 0;
  size_t               nscount = 0;
  size_t               arcount = 0;

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_create(&dnsrec, 0x1234,
      ARES_FLAG_QR|ARES_FLAG_AA|ARES_FLAG_RD|ARES_FLAG_RA,
      ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));

  /* == Question == */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_query_add(dnsrec, "example.com",
      ARES_REC_TYPE_ANY,
      ARES_CLASS_IN));

  /* == Answer == */
  /* A */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_A, ARES_CLASS_IN, 600));

  EXPECT_EQ(600, ares_dns_rr_get_ttl(rr));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_ttl(rr, 300));
  EXPECT_EQ(300, ares_dns_rr_get_ttl(rr));

  EXPECT_LT(0, ares_inet_pton(AF_INET, "1.1.1.1", &addr));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr));
  /* AAAA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_AAAA, ARES_CLASS_IN, 300));
  EXPECT_LT(0, ares_inet_pton(AF_INET6, "2600::4", &addr6));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_addr6(rr, ARES_RR_AAAA_ADDR, &addr6));
  /* MX */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_MX, ARES_CLASS_IN, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_MX_PREFERENCE, 10));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_MX_EXCHANGE, "mail.example.com"));
  /* CNAME */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_CNAME, ARES_CLASS_IN, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_CNAME_CNAME, "b.example.com"));
  /* TXT */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_TXT, ARES_CLASS_IN, 3600));
  const char txt1[] = "blah=here blah=there anywhere";
  const char txt2[] = "some other record";
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, (unsigned char *)txt1,
      sizeof(txt1)-1));
   EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, (unsigned char *)txt2,
      sizeof(txt2)-1));
  /* SIG */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_SIG, ARES_CLASS_ANY, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SIG_TYPE_COVERED, ARES_REC_TYPE_TXT));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_SIG_ALGORITHM, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_SIG_LABELS, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SIG_ORIGINAL_TTL, 3200));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SIG_EXPIRATION, (unsigned int)time(NULL)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SIG_INCEPTION, (unsigned int)time(NULL) - (86400 * 365)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SIG_KEY_TAG, 0x1234));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SIG_SIGNERS_NAME, "signer.example.com"));
  const unsigned char sig[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_SIG_SIGNATURE, sig, sizeof(sig)));


  /* == Authority == */
  /* NS */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_NS, ARES_CLASS_IN, 38400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, "ns1.example.com"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_NS, ARES_CLASS_IN, 38400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, "ns2.example.com"));
  /* SOA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_SOA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SOA_MNAME, "ns1.example.com"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SOA_RNAME, "tech\\.support.example.com"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_SERIAL, 2023110701));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_REFRESH, 28800));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_RETRY, 7200));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_EXPIRE, 604800));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_SOA_MINIMUM, 86400));

  /* == Additional */
  /* OPT */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "",
      ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_OPT_UDP_SIZE, 1280));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_OPT_VERSION, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_OPT_FLAGS, 0));
  unsigned char optval[] = { 'c', '-', 'a', 'r', 'e', 's' };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, 3 /* NSID */, optval, sizeof(optval)));
  /* PTR -- doesn't make sense, but ok */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "example.com",
      ARES_REC_TYPE_PTR, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_PTR_DNAME, "b.example.com"));
  /* HINFO */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "example.com",
      ARES_REC_TYPE_HINFO, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_HINFO_CPU, "Virtual"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_HINFO_OS, "Linux"));
  /* SRV */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_ldap.example.com", ARES_REC_TYPE_SRV, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SRV_PRIORITY, 100));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SRV_WEIGHT, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SRV_PORT, 389));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SRV_TARGET, "ldap.example.com"));
  /* TLSA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_443._tcp.example.com", ARES_REC_TYPE_TLSA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_CERT_USAGE, ARES_TLSA_USAGE_CA));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_SELECTOR, ARES_TLSA_SELECTOR_FULL));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_MATCH, ARES_TLSA_MATCH_SHA256));
  const unsigned char tlsa[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_TLSA_DATA, tlsa, sizeof(tlsa)));
  /* DS */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_DS, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_DS_KEY_TAG, 0x1234));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_DS_ALGORITHM,
      ARES_DNSSEC_ALGORITHM_RSASHA256));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_DS_DIGEST_TYPE, ARES_DS_DIGEST_SHA256));
  const unsigned char ds_digest[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_DS_DIGEST, ds_digest, sizeof(ds_digest)));
  /* SSHFP */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_SSHFP, ARES_CLASS_IN, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_SSHFP_ALGORITHM,
      ARES_SSHFP_ALGORITHM_RSA));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_SSHFP_FP_TYPE, ARES_SSHFP_FP_SHA256));
  const unsigned char sshfp_fp[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_SSHFP_FINGERPRINT, sshfp_fp,
      sizeof(sshfp_fp)));
  /* RRSIG */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_RRSIG, ARES_CLASS_ANY, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_RRSIG_TYPE_COVERED, ARES_REC_TYPE_A));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_RRSIG_ALGORITHM,
      ARES_DNSSEC_ALGORITHM_RSASHA256));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_RRSIG_LABELS, 2));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_RRSIG_ORIGINAL_TTL, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_RRSIG_EXPIRATION,
      (unsigned int)time(NULL)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u32(rr, ARES_RR_RRSIG_INCEPTION,
      (unsigned int)time(NULL) - (86400 * 365)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_RRSIG_KEY_TAG, 0x5678));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_RRSIG_SIGNERS_NAME, "example.com"));
  const unsigned char rrsig_sig[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_RRSIG_SIGNATURE, rrsig_sig,
      sizeof(rrsig_sig)));
  /* NSEC */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_NSEC, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NSEC_NEXT_DOMAIN, "next.example.com"));
  const unsigned char nsec_bitmap[] = { 0x00, 0x06, 0x40, 0x01, 0x00,
                                        0x00, 0x00, 0x03 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC_TYPE_BIT_MAPS, nsec_bitmap,
      sizeof(nsec_bitmap)));
  /* DNSKEY */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_DNSKEY, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_DNSKEY_FLAGS, 257));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_DNSKEY_PROTOCOL, 3));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_DNSKEY_ALGORITHM,
      ARES_DNSSEC_ALGORITHM_RSASHA256));
  const unsigned char dnskey_pk[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_DNSKEY_PUBLIC_KEY, dnskey_pk,
      sizeof(dnskey_pk)));
  /* NSEC3 */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "abc123.example.com", ARES_REC_TYPE_NSEC3, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_NSEC3_HASH_ALGORITHM,
      ARES_NSEC3_HASH_SHA1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_NSEC3_FLAGS, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_NSEC3_ITERATIONS, 10));
  const unsigned char nsec3_salt[] = { 0xaa, 0xbb, 0xcc, 0xdd };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_SALT, nsec3_salt,
      sizeof(nsec3_salt)));
  const unsigned char nsec3_next[] = {
    0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5, 0x4d, 0xf0, 0x34, 0xb9,
    0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_NEXT_HASHED_OWNER, nsec3_next,
      sizeof(nsec3_next)));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_TYPE_BIT_MAPS, nsec_bitmap,
      sizeof(nsec_bitmap)));
  /* NSEC3PARAM */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_NSEC3PARAM, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_NSEC3PARAM_HASH_ALGORITHM,
      ARES_NSEC3_HASH_SHA1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_NSEC3PARAM_FLAGS, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_NSEC3PARAM_ITERATIONS, 10));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC3PARAM_SALT, nsec3_salt,
      sizeof(nsec3_salt)));
  /* SVCB */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_1234._bar.example.com", ARES_REC_TYPE_SVCB, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_SVCB_PRIORITY, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_SVCB_TARGET, "svc1.example.net"));
  /* IPV6 hint is a list of IPV6 addresses in network byte order, concatenated */
  struct ares_addr svcb_addr;
  svcb_addr.family = AF_UNSPEC;
  size_t               svcb_ipv6hint_len = 0;
  const unsigned char *svcb_ipv6hint = (const unsigned char *)ares_dns_pton("2001:db8::1", &svcb_addr, &svcb_ipv6hint_len);
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_SVCB_PARAMS, ARES_SVCB_PARAM_IPV6HINT,
      svcb_ipv6hint, svcb_ipv6hint_len));
  /* Port is 16bit big endian format */
  unsigned short svcb_port = htons(1234);
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_SVCB_PARAMS, ARES_SVCB_PARAM_PORT,
      (const unsigned char *)&svcb_port, sizeof(svcb_port)));
  /* HTTPS */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_HTTPS, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_HTTPS_PRIORITY, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_HTTPS_TARGET, ""));

  /* In DNS string format which is 1 octet length indicator followed by string */
  const unsigned char https_alpn[] = { 0x02, 'h', '3' };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_opt(rr, ARES_RR_HTTPS_PARAMS, ARES_SVCB_PARAM_ALPN,
      https_alpn, sizeof(https_alpn)));
  /* URI */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "_ftp._tcp.example.com", ARES_REC_TYPE_URI, ARES_CLASS_IN, 3600));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_URI_PRIORITY, 10));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_URI_WEIGHT, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_URI_TARGET, "ftp://ftp.example.com/public"));
  /* CAA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_CAA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_CAA_CRITICAL, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_CAA_TAG, "issue"));
  unsigned char caa[] = "letsencrypt.org";
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_CAA_VALUE, caa, sizeof(caa)));
  /* NAPTR */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL,
      "example.com", ARES_REC_TYPE_NAPTR, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_ORDER, 100));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_NAPTR_PREFERENCE, 10));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_FLAGS, "S"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_SERVICES, "SIP+D2U"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_REGEXP,
      "!^.*$!sip:customer-service@example.com!"));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NAPTR_REPLACEMENT,
      "_sip._udp.example.com."));
  /* RAW_RR */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "",
      ARES_REC_TYPE_RAW_RR, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u16(rr, ARES_RR_RAW_RR_TYPE, 65432));
  unsigned char data[] = { 0x00 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_RAW_RR_DATA, data, sizeof(data)));

  qdcount = ares_dns_record_query_cnt(dnsrec);
  ancount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER);
  nscount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY);
  arcount = ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL);

  /* Write */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));

  ares_buf_t *hexdump = ares_buf_create();
  EXPECT_EQ(ARES_SUCCESS, ares_buf_hexdump(hexdump, msg, msglen));
  char *hexdata = ares_buf_finish_str(hexdump, NULL);
  //printf("HEXDUMP\n%s", hexdata);
  ares_free(hexdata);

  ares_dns_record_destroy(dnsrec); dnsrec = NULL;

  /* Parse */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, 0, &dnsrec));
  ares_free_string(msg); msg = NULL;

  /* Re-write */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));

  EXPECT_EQ(qdcount, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(ancount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));
  EXPECT_EQ(nscount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY));
  EXPECT_EQ(arcount, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));

  /* Verify record fields survived roundtrip */
  /* DS - index 5 */
  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 5);
  EXPECT_EQ(ARES_REC_TYPE_DS, ares_dns_rr_get_type(rr));
  EXPECT_EQ(0x1234, ares_dns_rr_get_u16(rr, ARES_RR_DS_KEY_TAG));
  EXPECT_EQ(ARES_DNSSEC_ALGORITHM_RSASHA256,
    ares_dns_rr_get_u8(rr, ARES_RR_DS_ALGORITHM));
  EXPECT_EQ(ARES_DS_DIGEST_SHA256,
    ares_dns_rr_get_u8(rr, ARES_RR_DS_DIGEST_TYPE));
  {
    size_t len = 0;
    const unsigned char *bin = ares_dns_rr_get_bin(rr, ARES_RR_DS_DIGEST, &len);
    EXPECT_EQ(32, len);
    EXPECT_NE(nullptr, bin);
    EXPECT_EQ(0xd2, bin[0]);
  }

  /* SSHFP - index 6 */
  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 6);
  EXPECT_EQ(ARES_REC_TYPE_SSHFP, ares_dns_rr_get_type(rr));
  EXPECT_EQ(ARES_SSHFP_ALGORITHM_RSA,
    ares_dns_rr_get_u8(rr, ARES_RR_SSHFP_ALGORITHM));
  EXPECT_EQ(ARES_SSHFP_FP_SHA256,
    ares_dns_rr_get_u8(rr, ARES_RR_SSHFP_FP_TYPE));
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_SSHFP_FINGERPRINT, &len);
    EXPECT_EQ(32, len);
    EXPECT_NE(nullptr, bin);
    EXPECT_EQ(0xd2, bin[0]);
  }

  /* RRSIG - index 7 */
  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 7);
  EXPECT_EQ(ARES_REC_TYPE_RRSIG, ares_dns_rr_get_type(rr));
  EXPECT_EQ(ARES_REC_TYPE_A,
    ares_dns_rr_get_u16(rr, ARES_RR_RRSIG_TYPE_COVERED));
  EXPECT_EQ(ARES_DNSSEC_ALGORITHM_RSASHA256,
    ares_dns_rr_get_u8(rr, ARES_RR_RRSIG_ALGORITHM));
  EXPECT_EQ(2, ares_dns_rr_get_u8(rr, ARES_RR_RRSIG_LABELS));
  EXPECT_EQ(3600, ares_dns_rr_get_u32(rr, ARES_RR_RRSIG_ORIGINAL_TTL));
  EXPECT_EQ(0x5678, ares_dns_rr_get_u16(rr, ARES_RR_RRSIG_KEY_TAG));
  EXPECT_STREQ("example.com",
    ares_dns_rr_get_str(rr, ARES_RR_RRSIG_SIGNERS_NAME));
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_RRSIG_SIGNATURE, &len);
    EXPECT_EQ(32, len);
    EXPECT_NE(nullptr, bin);
  }

  /* NSEC - index 8 */
  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 8);
  EXPECT_EQ(ARES_REC_TYPE_NSEC, ares_dns_rr_get_type(rr));
  EXPECT_STREQ("next.example.com",
    ares_dns_rr_get_str(rr, ARES_RR_NSEC_NEXT_DOMAIN));
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_NSEC_TYPE_BIT_MAPS, &len);
    EXPECT_EQ(8, len);
    EXPECT_NE(nullptr, bin);
  }

  /* DNSKEY - index 9 */
  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 9);
  EXPECT_EQ(ARES_REC_TYPE_DNSKEY, ares_dns_rr_get_type(rr));
  EXPECT_EQ(257, ares_dns_rr_get_u16(rr, ARES_RR_DNSKEY_FLAGS));
  EXPECT_EQ(3, ares_dns_rr_get_u8(rr, ARES_RR_DNSKEY_PROTOCOL));
  EXPECT_EQ(ARES_DNSSEC_ALGORITHM_RSASHA256,
    ares_dns_rr_get_u8(rr, ARES_RR_DNSKEY_ALGORITHM));
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_DNSKEY_PUBLIC_KEY, &len);
    EXPECT_EQ(32, len);
    EXPECT_NE(nullptr, bin);
  }

  /* NSEC3 - index 10 */
  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 10);
  EXPECT_EQ(ARES_REC_TYPE_NSEC3, ares_dns_rr_get_type(rr));
  EXPECT_EQ(ARES_NSEC3_HASH_SHA1,
    ares_dns_rr_get_u8(rr, ARES_RR_NSEC3_HASH_ALGORITHM));
  EXPECT_EQ(0, ares_dns_rr_get_u8(rr, ARES_RR_NSEC3_FLAGS));
  EXPECT_EQ(10, ares_dns_rr_get_u16(rr, ARES_RR_NSEC3_ITERATIONS));
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_NSEC3_SALT, &len);
    EXPECT_EQ(4, len);
    EXPECT_NE(nullptr, bin);
    EXPECT_EQ(0xaa, bin[0]);
  }
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_NSEC3_NEXT_HASHED_OWNER, &len);
    EXPECT_EQ(20, len);
    EXPECT_NE(nullptr, bin);
    EXPECT_EQ(0x0d, bin[0]);
  }
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_NSEC3_TYPE_BIT_MAPS, &len);
    EXPECT_EQ(8, len);
    EXPECT_NE(nullptr, bin);
  }

  /* NSEC3PARAM - index 11 */
  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 11);
  EXPECT_EQ(ARES_REC_TYPE_NSEC3PARAM, ares_dns_rr_get_type(rr));
  EXPECT_EQ(ARES_NSEC3_HASH_SHA1,
    ares_dns_rr_get_u8(rr, ARES_RR_NSEC3PARAM_HASH_ALGORITHM));
  EXPECT_EQ(0, ares_dns_rr_get_u8(rr, ARES_RR_NSEC3PARAM_FLAGS));
  EXPECT_EQ(10, ares_dns_rr_get_u16(rr, ARES_RR_NSEC3PARAM_ITERATIONS));
  {
    size_t len = 0;
    const unsigned char *bin =
      ares_dns_rr_get_bin(rr, ARES_RR_NSEC3PARAM_SALT, &len);
    EXPECT_EQ(4, len);
    EXPECT_NE(nullptr, bin);
    EXPECT_EQ(0xaa, bin[0]);
  }

  /* Iterate and print */
  ares_buf_t *printmsg = ares_buf_create();
  ares_buf_append_str(printmsg, ";; ->>HEADER<<- opcode: ");
  ares_buf_append_str(printmsg, ares_dns_opcode_tostr(ares_dns_record_get_opcode(dnsrec)));
  ares_buf_append_str(printmsg, ", status: ");
  ares_buf_append_str(printmsg, ares_dns_rcode_tostr(ares_dns_record_get_rcode(dnsrec)));
  ares_buf_append_str(printmsg, ", id: ");
  ares_buf_append_num_dec(printmsg, (size_t)ares_dns_record_get_id(dnsrec), 0);
  ares_buf_append_str(printmsg, "\n;; flags: ");
  ares_buf_append_num_hex(printmsg, (size_t)ares_dns_record_get_flags(dnsrec), 0);
  ares_buf_append_str(printmsg, "; QUERY: ");
  ares_buf_append_num_dec(printmsg, ares_dns_record_query_cnt(dnsrec), 0);
  ares_buf_append_str(printmsg, ", ANSWER: ");
  ares_buf_append_num_dec(printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER), 0);
  ares_buf_append_str(printmsg, ", AUTHORITY: ");
  ares_buf_append_num_dec(printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY), 0);
  ares_buf_append_str(printmsg, ", ADDITIONAL: ");
  ares_buf_append_num_dec(printmsg, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL), 0);
  ares_buf_append_str(printmsg, "\n\n");
  ares_buf_append_str(printmsg, ";; QUESTION SECTION:\n");
  for (size_t i = 0; i < ares_dns_record_query_cnt(dnsrec); i++) {
    const char         *name;
    ares_dns_rec_type_t qtype;
    ares_dns_class_t    qclass;
    ares_dns_record_query_get(dnsrec, i, &name, &qtype, &qclass);
    ares_buf_append_str(printmsg, ";");
    ares_buf_append_str(printmsg, name);
    ares_buf_append_str(printmsg, ".\t\t\t");
    ares_buf_append_str(printmsg, ares_dns_class_tostr(qclass));
    ares_buf_append_str(printmsg, "\t");
    ares_buf_append_str(printmsg, ares_dns_rec_type_tostr(qtype));
    ares_buf_append_str(printmsg, "\n");
  }
  ares_buf_append_str(printmsg, "\n");
  for (size_t i = ARES_SECTION_ANSWER; i < ARES_SECTION_ADDITIONAL + 1; i++) {
    ares_buf_append_str(printmsg, ";; ");
    ares_buf_append_str(printmsg, ares_dns_section_tostr((ares_dns_section_t)i));
    ares_buf_append_str(printmsg, " SECTION:\n");
    for (size_t j = 0; j < ares_dns_record_rr_cnt(dnsrec, (ares_dns_section_t)i); j++) {
      rr = ares_dns_record_rr_get(dnsrec, (ares_dns_section_t)i, j);
      ares_buf_append_str(printmsg, ares_dns_rr_get_name(rr));
      ares_buf_append_str(printmsg, ".\t\t\t");
      ares_buf_append_str(printmsg, ares_dns_class_tostr(ares_dns_rr_get_class(rr)));
      ares_buf_append_str(printmsg, "\t");
      ares_buf_append_str(printmsg, ares_dns_rec_type_tostr(ares_dns_rr_get_type(rr)));
      ares_buf_append_str(printmsg, "\t");
      ares_buf_append_num_dec(printmsg, ares_dns_rr_get_ttl(rr), 0);
      ares_buf_append_str(printmsg, "\t");

      size_t keys_cnt;
      const ares_dns_rr_key_t *keys = ares_dns_rr_get_keys(ares_dns_rr_get_type(rr), &keys_cnt);
      for (size_t k = 0; k<keys_cnt; k++) {
        char buf[256] = "";
        ares_buf_append_str(printmsg, ares_dns_rr_key_tostr(keys[k]));
        ares_buf_append_str(printmsg, "=");
        switch (ares_dns_rr_key_datatype(keys[k])) {
          case ARES_DATATYPE_INADDR:
            ares_inet_ntop(AF_INET, ares_dns_rr_get_addr(rr, keys[k]), buf, sizeof(buf));
            ares_buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_INADDR6:
            ares_inet_ntop(AF_INET6, ares_dns_rr_get_addr6(rr, keys[k]), buf, sizeof(buf));
            ares_buf_append_str(printmsg, buf);
            break;
          case ARES_DATATYPE_U8:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u8(rr, keys[k]), 0);
            break;
          case ARES_DATATYPE_U16:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u16(rr, keys[k]), 0);
            break;
          case ARES_DATATYPE_U32:
            ares_buf_append_num_dec(printmsg, ares_dns_rr_get_u32(rr, keys[k]), 0);
            break;
          case ARES_DATATYPE_NAME:
          case ARES_DATATYPE_STR:
            ares_buf_append_byte(printmsg, '"');
            ares_buf_append_str(printmsg, ares_dns_rr_get_str(rr, keys[k]));
            ares_buf_append_byte(printmsg, '"');
            break;
          case ARES_DATATYPE_BIN:
            /* TODO */
            break;
          case ARES_DATATYPE_BINP:
            {
              ares_buf_append_byte(printmsg, '"');
              size_t templen;
              ares_buf_append_str(printmsg, (const char *)ares_dns_rr_get_bin(rr, keys[k], &templen));
              ares_buf_append_byte(printmsg, '"');
            }
            break;
          case ARES_DATATYPE_ABINP:
            for (size_t a=0; a<ares_dns_rr_get_abin_cnt(rr, keys[k]); a++) {
              if (a != 0) {
                ares_buf_append_byte(printmsg, ' ');
              }
              ares_buf_append_byte(printmsg, '"');
              size_t templen;
              ares_buf_append_str(printmsg, (const char *)ares_dns_rr_get_abin(rr, keys[k], a, &templen));
              ares_buf_append_byte(printmsg, '"');
            }
            break;
          case ARES_DATATYPE_OPT:
            /* TODO */
            break;
        }
        ares_buf_append_str(printmsg, " ");
      }
      ares_buf_append_str(printmsg, "\n");
    }
  }
  ares_buf_append_str(printmsg, ";; SIZE: ");
  ares_buf_append_num_dec(printmsg, msglen, 0);
  ares_buf_append_str(printmsg, "\n\n");

  char *printdata = ares_buf_finish_str(printmsg, NULL);
  //printf("%s", printdata);
  ares_free(printdata);

  ares_dns_record_destroy(dnsrec);
  ares_free_string(msg);

  // Invalid
  EXPECT_NE(ARES_SUCCESS, ares_dns_parse(NULL, 0, 0, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_create(NULL, 0, 0, ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  EXPECT_EQ(0, ares_dns_record_get_id(NULL));
  EXPECT_EQ(0, ares_dns_record_get_flags(NULL));
  EXPECT_EQ(0, (int)ares_dns_record_get_opcode(NULL));
  EXPECT_EQ(0, (int)ares_dns_record_get_rcode(NULL));
  EXPECT_EQ(0, (int)ares_dns_record_query_cnt(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_query_set_name(NULL, 0, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_query_set_type(NULL, 0, ARES_REC_TYPE_A));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_query_get(NULL, 0, NULL, NULL, NULL));
  EXPECT_EQ(0, ares_dns_record_rr_cnt(NULL, ARES_SECTION_ANSWER));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_rr_add(NULL, NULL, ARES_SECTION_ANSWER, NULL, ARES_REC_TYPE_A, ARES_CLASS_IN, 0));
  EXPECT_NE(ARES_SUCCESS, ares_dns_record_rr_del(NULL, ARES_SECTION_ANSWER, 0));
  EXPECT_EQ(nullptr, ares_dns_record_rr_get(NULL, ARES_SECTION_ANSWER, 0));
  EXPECT_EQ(nullptr, ares_dns_rr_get_name(NULL));
  EXPECT_EQ(0, (int)ares_dns_rr_get_type(NULL));
  EXPECT_EQ(0, (int)ares_dns_rr_get_class(NULL));
  EXPECT_EQ(0, ares_dns_rr_get_ttl(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_dns_rr_set_ttl(NULL, 100));
  EXPECT_NE(ARES_SUCCESS, ares_dns_write(NULL, NULL, NULL));
#ifndef CARES_SYMBOL_HIDING
  ares_dns_record_ttl_decrement(NULL, 0);
#endif
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr(NULL, ARES_RR_A_ADDR));
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr6(NULL, ARES_RR_AAAA_ADDR));
  EXPECT_EQ(nullptr, ares_dns_rr_get_addr6(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(0, ares_dns_rr_get_u8(NULL, ARES_RR_SIG_ALGORITHM));
  EXPECT_EQ(0, ares_dns_rr_get_u8(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(0, ares_dns_rr_get_u16(NULL, ARES_RR_MX_PREFERENCE));
  EXPECT_EQ(0, ares_dns_rr_get_u16(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(0, ares_dns_rr_get_u32(NULL, ARES_RR_SOA_SERIAL));
  EXPECT_EQ(0, ares_dns_rr_get_u32(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ares_dns_rr_get_bin(NULL, ARES_RR_TXT_DATA, NULL));
  EXPECT_EQ(nullptr, ares_dns_rr_get_bin(NULL, ARES_RR_NS_NSDNAME, NULL));
  EXPECT_EQ(nullptr, ares_dns_rr_get_str(NULL, ARES_RR_NS_NSDNAME));
  EXPECT_EQ(nullptr, ares_dns_rr_get_str(NULL, ARES_RR_MX_PREFERENCE));
  EXPECT_EQ(0, ares_dns_rr_get_opt_cnt(NULL, ARES_RR_OPT_OPTIONS));
  EXPECT_EQ(0, ares_dns_rr_get_opt_cnt(NULL, ARES_RR_A_ADDR));
  EXPECT_EQ(65535, ares_dns_rr_get_opt(NULL, ARES_RR_OPT_OPTIONS, 0, NULL, NULL));
  EXPECT_EQ(65535, ares_dns_rr_get_opt(NULL, ARES_RR_A_ADDR, 0, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_dns_rr_get_opt_byid(NULL, ARES_RR_OPT_OPTIONS, 1, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_dns_rr_get_opt_byid(NULL, ARES_RR_A_ADDR, 1, NULL, NULL));
}

TEST_F(LibraryTest, DNSNameCompression14Bit) {
  ares_dns_record_t          *dnsrec = NULL;
  ares_dns_rr_t              *rr     = NULL;
  unsigned char              *msg    = NULL;
  size_t                      msglen = 0;
  std::vector<unsigned char>  txt(255, 'a');

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_create(&dnsrec, 0x1234, ARES_FLAG_QR,
      ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_query_add(dnsrec, "example.com", ARES_REC_TYPE_ANY,
      ARES_CLASS_IN));

  /* Pad the message well past the 14-bit (16383 byte) compression pointer
   * limit with large TXT records. */
  for (size_t i = 0; i < 80; i++) {
    EXPECT_EQ(ARES_SUCCESS,
      ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
        ARES_REC_TYPE_TXT, ARES_CLASS_IN, 0));
    EXPECT_EQ(ARES_SUCCESS,
      ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, txt.data(), txt.size()));
  }

  /* Past byte 16383, add a repeated owner name.  Its first occurrence lands at
   * an offset that doesn't fit in 14 bits, so it must not be recorded as a
   * compression target; the second occurrence must not be emitted as a pointer
   * to (offset & 0x3FFF), which would corrupt the message.  It instead
   * compresses only against the in-range example.com target. */
  for (size_t i = 0; i < 2; i++) {
    EXPECT_EQ(ARES_SUCCESS,
      ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
        "repeat.example.com", ARES_REC_TYPE_TXT, ARES_CLASS_IN, 0));
    EXPECT_EQ(ARES_SUCCESS,
      ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, txt.data(), txt.size()));
  }

  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));
  EXPECT_GT(msglen, 0x3FFFU);

  /* 12 hdr + 17 question + 80*268 compressed TXT + 2*275 repeat TXT.
   * An exact size also verifies compression remains active for names
   * below the limit. */
  EXPECT_EQ(22019U, msglen);

  /* Before the fix this parse failed / mis-parsed on the truncated pointer. */
  ares_dns_record_t *parsed = NULL;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, 0, &parsed));
  ASSERT_NE(nullptr, parsed);

  size_t ancount = ares_dns_record_rr_cnt(parsed, ARES_SECTION_ANSWER);
  EXPECT_EQ(82U, ancount);
  const ares_dns_rr_t *last =
    ares_dns_record_rr_get_const(parsed, ARES_SECTION_ANSWER, ancount - 1);
  ASSERT_NE(nullptr, last);
  EXPECT_STREQ("repeat.example.com", ares_dns_rr_get_name(last));

  ares_dns_record_destroy(parsed);
  ares_free_string(msg);
  ares_dns_record_destroy(dnsrec);
}

#ifndef CARES_SYMBOL_HIDING
/* Regression coverage for the zero-length salt/type-bitmap code paths in
* NSEC3 and NSEC3PARAM (empty non-terminal / opt-out per RFC 5155 7.1),
* which the parser represents via ares_dns_rr_set_bin_own(..., NULL, 0).
* That internal API isn't exported from shared builds with symbol hiding
* enabled, so this test is skipped in that configuration. */
TEST_F(LibraryTest, DNSRecordNSEC3EmptyFields) {
 ares_dns_record_t *dnsrec = NULL;
 ares_dns_rr_t     *rr     = NULL;

 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_record_create(&dnsrec, 0x1234, 0, ARES_OPCODE_QUERY,
                           ARES_RCODE_NOERROR));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_record_query_add(dnsrec, "example.com", ARES_REC_TYPE_NSEC3,
                              ARES_CLASS_IN));

 /* NSEC3 with empty salt and empty type bitmap. */
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
     "def456.example.com", ARES_REC_TYPE_NSEC3, ARES_CLASS_IN, 86400));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_u8(rr, ARES_RR_NSEC3_HASH_ALGORITHM,
     ARES_NSEC3_HASH_SHA1));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_u8(rr, ARES_RR_NSEC3_FLAGS, 1));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_u16(rr, ARES_RR_NSEC3_ITERATIONS, 10));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_SALT, NULL, 0));
 const unsigned char nsec3_next[] = {
   0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5, 0x4d, 0xf0, 0x34, 0xb9,
   0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e };
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_NEXT_HASHED_OWNER, nsec3_next,
     sizeof(nsec3_next)));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_TYPE_BIT_MAPS,
                       (const unsigned char *)"", 0));

 /* NSEC3PARAM with empty salt. */
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
     "example.com", ARES_REC_TYPE_NSEC3PARAM, ARES_CLASS_IN, 0));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_u8(rr, ARES_RR_NSEC3PARAM_HASH_ALGORITHM,
     ARES_NSEC3_HASH_SHA1));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_u8(rr, ARES_RR_NSEC3PARAM_FLAGS, 0));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_u16(rr, ARES_RR_NSEC3PARAM_ITERATIONS, 10));
 EXPECT_EQ(ARES_SUCCESS,
   ares_dns_rr_set_bin(rr, ARES_RR_NSEC3PARAM_SALT, NULL, 0));

 /* Write and re-parse to exercise the write-side empty-length paths too. */
 unsigned char *buf    = NULL;
 size_t         buflen = 0;
 EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &buf, &buflen));

 ares_dns_record_t *parsed = NULL;
 EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(buf, buflen, 0, &parsed));

 rr = ares_dns_record_rr_get(parsed, ARES_SECTION_ANSWER, 0);
 EXPECT_EQ(ARES_REC_TYPE_NSEC3, ares_dns_rr_get_type(rr));
 {
   size_t len = 1;
   ares_dns_rr_get_bin(rr, ARES_RR_NSEC3_SALT, &len);
   EXPECT_EQ((size_t)0, len);
 }
 {
   size_t len = 1;
   ares_dns_rr_get_bin(rr, ARES_RR_NSEC3_TYPE_BIT_MAPS, &len);
   EXPECT_EQ((size_t)0, len);
 }

 rr = ares_dns_record_rr_get(parsed, ARES_SECTION_ANSWER, 1);
 EXPECT_EQ(ARES_REC_TYPE_NSEC3PARAM, ares_dns_rr_get_type(rr));
 {
   size_t len = 1;
   ares_dns_rr_get_bin(rr, ARES_RR_NSEC3PARAM_SALT, &len);
   EXPECT_EQ((size_t)0, len);
 }

 ares_free(buf);
 ares_dns_record_destroy(parsed);
 ares_dns_record_destroy(dnsrec);
}
#endif /* !CARES_SYMBOL_HIDING */

TEST_F(LibraryTest, DNSRecordRejectsInvalidBinaryInput) {
  ares_dns_record_t *dnsrec = NULL;
  ares_dns_rr_t     *rr     = NULL;
  unsigned char      data[] = { 'x' };

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_create(&dnsrec, 0x1234, ARES_FLAG_RD,
      ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_TXT, ARES_CLASS_IN, 60));
  EXPECT_EQ(ARES_ENOMEM,
    ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, data, SIZE_MAX));
  EXPECT_EQ(ARES_EFORMERR,
    ares_dns_rr_add_abin(rr, ARES_RR_TXT_DATA, NULL, 1));

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_CAA, ARES_CLASS_IN, 60));
  EXPECT_EQ(ARES_ENOMEM,
    ares_dns_rr_set_bin(rr, ARES_RR_CAA_VALUE, data, SIZE_MAX));
  EXPECT_EQ(ARES_EFORMERR,
    ares_dns_rr_set_bin(rr, ARES_RR_CAA_VALUE, NULL, 1));
  EXPECT_EQ(ARES_EFORMERR,
    ares_dns_rr_set_bin(rr, ARES_RR_CAA_TAG, data, sizeof(data)));

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "",
      ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0));
  EXPECT_EQ(ARES_ENOMEM,
    ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, 3, data, SIZE_MAX));
  EXPECT_EQ(ARES_EFORMERR,
    ares_dns_rr_set_opt(rr, ARES_RR_OPT_OPTIONS, 3, NULL, 1));

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_NSEC3, ARES_CLASS_IN, 60));
  EXPECT_EQ(ARES_EFORMERR,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_SALT, NULL, 1));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_SALT, NULL, 0));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_NSEC3_SALT, (const unsigned char *)"", 0));
#ifndef CARES_SYMBOL_HIDING
  EXPECT_EQ(ARES_EFORMERR,
    ares_dns_rr_set_bin_own(rr, ARES_RR_NSEC3_SALT, NULL, 1));
#endif

  ares_dns_record_destroy(dnsrec);
}

TEST_F(LibraryTest, DNSParseFlags) {
  ares_dns_record_t   *dnsrec = NULL;
  ares_dns_rr_t       *rr     = NULL;
  struct in_addr       addr;
  unsigned char       *msg    = NULL;
  size_t               msglen = 0;

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_create(&dnsrec, 0x1234,
      ARES_FLAG_QR|ARES_FLAG_AA|ARES_FLAG_RD|ARES_FLAG_RA,
      ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));

  /* == Question == */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_query_add(dnsrec, "example.com",
      ARES_REC_TYPE_ANY,
      ARES_CLASS_IN));

  /* == Answer == */
  /* A */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER, "example.com",
      ARES_REC_TYPE_A, ARES_CLASS_IN, 300));
  EXPECT_LT(0, ares_inet_pton(AF_INET, "1.1.1.1", &addr));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_addr(rr, ARES_RR_A_ADDR, &addr));
  /* TLSA */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
      "_443._tcp.example.com", ARES_REC_TYPE_TLSA, ARES_CLASS_IN, 86400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_CERT_USAGE, ARES_TLSA_USAGE_CA));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_SELECTOR, ARES_TLSA_SELECTOR_FULL));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_u8(rr, ARES_RR_TLSA_MATCH, ARES_TLSA_MATCH_SHA256));
  const unsigned char tlsa[] = {
    0xd2, 0xab, 0xde, 0x24, 0x0d, 0x7c, 0xd3, 0xee, 0x6b, 0x4b, 0x28, 0xc5,
    0x4d, 0xf0, 0x34, 0xb9, 0x79, 0x83, 0xa1, 0xd1, 0x6e, 0x8a, 0x41, 0x0e,
    0x45, 0x61, 0xcb, 0x10, 0x66, 0x18, 0xe9, 0x71 };
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_bin(rr, ARES_RR_TLSA_DATA, tlsa, sizeof(tlsa)));

  /* == Authority == */
  /* NS */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_AUTHORITY, "example.com",
      ARES_REC_TYPE_NS, ARES_CLASS_IN, 38400));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_NS_NSDNAME, "ns1.example.com"));

  /* == Additional */
  /* PTR -- doesn't make sense, but ok */
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ADDITIONAL, "example.com",
      ARES_REC_TYPE_PTR, ARES_CLASS_IN, 300));
  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_rr_set_str(rr, ARES_RR_PTR_DNAME, "b.example.com"));

  /* Write */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &msg, &msglen));

  /* Cleanup - before reuse */
  ares_dns_record_destroy(dnsrec);

  /* Parse "base" type records (1035) */
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, ARES_DNS_PARSE_AN_BASE_RAW |
    ARES_DNS_PARSE_NS_BASE_RAW | ARES_DNS_PARSE_AR_BASE_RAW, &dnsrec));

  EXPECT_EQ(1, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(2, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 0);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 1);
  EXPECT_EQ(ARES_REC_TYPE_TLSA, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_AUTHORITY, 0);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 0);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  /* Cleanup - before reuse */

  ares_dns_record_destroy(dnsrec);

  /* Parse later RFCs (no name compression) type records */

  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(msg, msglen, ARES_DNS_PARSE_AN_EXT_RAW |
    ARES_DNS_PARSE_NS_EXT_RAW | ARES_DNS_PARSE_AR_EXT_RAW, &dnsrec));

  EXPECT_EQ(1, ares_dns_record_query_cnt(dnsrec));
  EXPECT_EQ(2, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ANSWER));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_AUTHORITY));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(dnsrec, ARES_SECTION_ADDITIONAL));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 0);
  EXPECT_EQ(ARES_REC_TYPE_A, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ANSWER, 1);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_AUTHORITY, 0);
  EXPECT_EQ(ARES_REC_TYPE_NS, ares_dns_rr_get_type(rr));

  rr = ares_dns_record_rr_get(dnsrec, ARES_SECTION_ADDITIONAL, 0);
  EXPECT_EQ(ARES_REC_TYPE_PTR, ares_dns_rr_get_type(rr));

  ares_dns_record_destroy(dnsrec);
  ares_free_string(msg); msg = NULL;
}

TEST_F(LibraryTest, ArrayMisuse) {
  EXPECT_EQ(NULL, ares_array_create(0, NULL));
  ares_array_destroy(NULL);
  EXPECT_EQ(NULL, ares_array_finish(NULL, NULL));
  EXPECT_EQ(0, ares_array_len(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_insert_at(NULL, NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares_array_insertdata_at(NULL, 0, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_insert_last(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_insertdata_last(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_insert_first(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_insertdata_first(NULL, NULL));
  EXPECT_EQ(NULL, ares_array_at(NULL, 0));
  EXPECT_EQ(NULL, ares_array_first(NULL));
  EXPECT_EQ(NULL, ares_array_last(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_claim_at(NULL, 0, NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares_array_remove_at(NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares_array_remove_first(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_remove_last(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_sort(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_array_set_size(NULL, 0));

  /* Overflow in the size calculation must be rejected, not wrapped */
  ares_array_t *overflow_array = ares_array_create((SIZE_MAX / 2) + 1, NULL);
  EXPECT_NE((void *)NULL, overflow_array);
  EXPECT_EQ(ARES_ENOMEM, ares_array_set_size(overflow_array, 2));
  EXPECT_EQ(ARES_ENOMEM, ares_array_set_size(overflow_array, SIZE_MAX));
  ares_array_destroy(overflow_array);

  /* Overflow must also be rejected in the malloc-style wrapper, and in
   * the original-size arm of the realloc wrapper */
  EXPECT_EQ(NULL, ares_malloc_zero_array(SIZE_MAX, 2));
  EXPECT_EQ(NULL, ares_malloc_zero_array(2, SIZE_MAX));
  EXPECT_EQ(NULL, ares_realloc_zero_array(NULL, SIZE_MAX, 1, 2));
  EXPECT_EQ(NULL, ares_malloc_array(SIZE_MAX, 2));
  EXPECT_EQ(NULL, ares_malloc_array(2, SIZE_MAX));
  EXPECT_EQ(NULL, ares_realloc_array(NULL, SIZE_MAX, 2));
  EXPECT_EQ(NULL, ares_realloc_array(NULL, 2, SIZE_MAX));
}

TEST_F(LibraryTest, ArrayAlloc) {
  unsigned int *arr;
  unsigned int *grown;
  size_t        i;

  arr = (unsigned int *)ares_malloc_array(4, sizeof(*arr));
  ASSERT_NE((void *)NULL, arr);
  for (i = 0; i < 4; i++) {
    arr[i] = (unsigned int)i;
  }

  /* A rejected resize must leave the original array intact and owned by the
   * caller, exactly like a failed realloc() */
  EXPECT_EQ(NULL, ares_realloc_array(arr, SIZE_MAX, sizeof(*arr)));
  EXPECT_EQ(NULL, ares_realloc_array(arr, 0, sizeof(*arr)));
  EXPECT_EQ(NULL, ares_realloc_zero_array(arr, 4, 0, sizeof(*arr)));
  for (i = 0; i < 4; i++) {
    EXPECT_EQ((unsigned int)i, arr[i]);
  }

  grown = (unsigned int *)ares_realloc_array(arr, 8, sizeof(*arr));
  ASSERT_NE((void *)NULL, grown);
  arr = grown;
  for (i = 0; i < 4; i++) {
    EXPECT_EQ((unsigned int)i, arr[i]);
  }
  ares_free(arr);

  /* NULL behaves like a fresh allocation */
  arr = (unsigned int *)ares_realloc_array(NULL, 2, sizeof(*arr));
  ASSERT_NE((void *)NULL, arr);
  ares_free(arr);
}

/* Choose num so that num * sizeof(char *) wraps to exactly
 * 2 * sizeof(char *) on any size_t width, then arm an allocation failure for
 * that wrapped size.  An unchecked multiplication hands the wrapped size to
 * the allocator and consumes the armed failure (safely returning NULL); a
 * checked one rejects the request before the allocator is ever called. */
static const size_t wrapped_array_size = 2 * sizeof(char *);
static const size_t wrapping_array_num = (SIZE_MAX / sizeof(char *)) + 3;

TEST_F(LibraryTest, ArrayAllocOverflowNeverReachesAllocator) {
  void *ptr = NULL;

  SetAllocSizeFail(wrapped_array_size);
  EXPECT_EQ(NULL, ares_malloc_array(wrapping_array_num, sizeof(char *)));
  EXPECT_EQ(NULL, ares_malloc_zero_array(wrapping_array_num, sizeof(char *)));
  EXPECT_EQ(NULL, ares_realloc_array(ptr, wrapping_array_num, sizeof(char *)));
  EXPECT_EQ(NULL, ares_realloc_zero_array(ptr, 0, wrapping_array_num,
                                          sizeof(char *)));
  EXPECT_TRUE(AllocSizeFailPending(wrapped_array_size));
}

#if SIZE_MAX <= 0xFFFFFFFFUL
/* Same check driven through the public API.  ares_options.nsort is an int
 * supplied by the application, and on a 32-bit size_t
 * nsort * sizeof(struct apattern) can wrap while nsort still fits in an int.
 * Pick nsort so the product wraps to a small, distinctive size and arm a
 * failure for exactly that size.  Without the overflow check the allocator is
 * asked for the wrapped size, and the copy loop that follows would write
 * nsort entries into it; with the check, init fails before allocating. */
TEST_F(LibraryTest, InitSortlistCountOverflow) {
  struct ares_options opts;
  struct apattern     pattern;
  ares_channel_t     *channel = NULL;
  size_t              nsort;
  size_t              wrapped;

  nsort   = (SIZE_MAX / sizeof(struct apattern)) + 1 + 1000;
  wrapped = nsort * sizeof(struct apattern); /* wraps by construction */
  ASSERT_LE(nsort, (size_t)INT_MAX);
  ASSERT_LT(wrapped, nsort);

  memset(&opts, 0, sizeof(opts));
  memset(&pattern, 0, sizeof(pattern));
  opts.nsort    = (int)nsort;
  opts.sortlist = &pattern;

  SetAllocSizeFail(wrapped);
  EXPECT_EQ(ARES_ENOMEM,
            ares_init_options(&channel, &opts, ARES_OPT_SORTLIST));
  EXPECT_EQ(nullptr, channel);
  EXPECT_TRUE(AllocSizeFailPending(wrapped));
}
#endif

TEST_F(LibraryTest, BufMisuse) {
  EXPECT_EQ(NULL, ares_buf_create_const(NULL, 0));
  ares_buf_reclaim(NULL);
  EXPECT_NE(ARES_SUCCESS, ares_buf_append(NULL, NULL, 55));
  size_t len = 10;
  EXPECT_EQ(NULL, ares_buf_append_start(NULL, &len));
  EXPECT_EQ(NULL, ares_buf_append_start(NULL, NULL));
  ares_buf_append_finish(NULL, 0);
  EXPECT_EQ(NULL, ares_buf_finish_bin(NULL, NULL));
  EXPECT_EQ(NULL, ares_buf_finish_str(NULL, NULL));
  ares_buf_tag(NULL);
  EXPECT_NE(ARES_SUCCESS, ares_buf_tag_rollback(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_buf_tag_clear(NULL));
  EXPECT_EQ(NULL, ares_buf_tag_fetch(NULL, NULL));
  EXPECT_EQ((size_t)0, ares_buf_tag_length(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_buf_tag_fetch_bytes(NULL, NULL, NULL));
  EXPECT_NE(ARES_SUCCESS,
            ares_buf_tag_fetch_string(NULL, NULL, 0, ARES_BUF_CHARSET_ASCII));
  EXPECT_NE(ARES_SUCCESS,
            ares_buf_tag_fetch_strdup(NULL, NULL, ARES_BUF_CHARSET_UTF8));
  EXPECT_NE(ARES_SUCCESS, ares_buf_fetch_bytes_dup(NULL, 0, ARES_FALSE, NULL));
  EXPECT_NE(ARES_SUCCESS,
            ares_buf_fetch_str_dup(NULL, 0, NULL, ARES_BUF_CHARSET_ASCII));
  EXPECT_EQ((size_t)0, ares_buf_consume_whitespace(NULL, ARES_FALSE));
  EXPECT_EQ((size_t)0, ares_buf_consume_nonwhitespace(NULL));
  EXPECT_EQ((size_t)0, ares_buf_consume_line(NULL, ARES_FALSE));
  EXPECT_NE(ARES_SUCCESS, ares_buf_append_codepoint(NULL, 0x41));
  EXPECT_NE(ARES_SUCCESS, ares_buf_fetch_codepoint(NULL, NULL));
  EXPECT_NE(ARES_SUCCESS, ares_buf_len_utf8(NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_buf_isprint(NULL));
  EXPECT_EQ((size_t)0,
            ares_buf_consume_last_charset(NULL, NULL, 0, ARES_FALSE));
  EXPECT_EQ(SIZE_MAX, ares_buf_consume_last_charset(NULL, NULL, 0, ARES_TRUE));
  EXPECT_EQ(ARES_FALSE, ares_buf_begins_with(NULL, NULL, 0));
  EXPECT_EQ((size_t)0, ares_buf_get_position(NULL));
  EXPECT_NE(ARES_SUCCESS, ares_buf_set_position(NULL, 0));
  EXPECT_NE(ARES_SUCCESS, ares_buf_parse_dns_binstr(NULL, 0, NULL, NULL));
}

TEST_F(LibraryTest, HtableAsvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares_htable_asvp_insert(NULL, ARES_SOCKET_BAD, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_asvp_get(NULL, ARES_SOCKET_BAD, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_asvp_remove(NULL, ARES_SOCKET_BAD));
  EXPECT_EQ((size_t)0, ares_htable_asvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableStrvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares_htable_strvp_insert(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_strvp_get(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_strvp_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares_htable_strvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableVpStrMisuse) {
  EXPECT_EQ(ARES_FALSE, ares_htable_vpstr_insert(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_vpstr_get(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_vpstr_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares_htable_vpstr_num_keys(NULL));
}

TEST_F(LibraryTest, HtableDictMisuse) {
  EXPECT_EQ(ARES_FALSE, ares_htable_dict_insert(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_dict_get(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_dict_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares_htable_dict_num_keys(NULL));
}

TEST_F(LibraryTest, HtableSzvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares_htable_szvp_insert(NULL, 0, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_szvp_get(NULL, 0, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_szvp_remove(NULL, 0));
  EXPECT_EQ((size_t)0, ares_htable_szvp_num_keys(NULL));
}

TEST_F(LibraryTest, HtableVpvpMisuse) {
  EXPECT_EQ(ARES_FALSE, ares_htable_vpvp_insert(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_vpvp_get(NULL, NULL, NULL));
  EXPECT_EQ(ARES_FALSE, ares_htable_vpvp_remove(NULL, NULL));
  EXPECT_EQ((size_t)0, ares_htable_vpvp_num_keys(NULL));
}

TEST_F(LibraryTest, LlistMisuse) {
  ares_llist_replace_destructor(NULL, NULL);
  EXPECT_EQ(NULL, ares_llist_insert_before(NULL, NULL));
  EXPECT_EQ(NULL, ares_llist_insert_after(NULL, NULL));
  EXPECT_EQ(NULL, ares_llist_node_last(NULL));
  EXPECT_EQ(NULL, ares_llist_node_next(NULL));
  EXPECT_EQ(NULL, ares_llist_node_prev(NULL));
  EXPECT_EQ((size_t)0, ares_llist_len(NULL));
  EXPECT_EQ(NULL, ares_llist_node_parent(NULL));
  EXPECT_EQ(NULL, ares_llist_node_claim(NULL));
  ares_llist_node_replace(NULL, NULL);
}

typedef struct {
  unsigned int id;
  ares_buf_t *buf;
} array_member_t;

static void array_member_init(void *mb, unsigned int id)
{
  array_member_t *m = (array_member_t *)mb;
  m->id             = id;
  m->buf            = ares_buf_create();
  ares_buf_append_be32(m->buf, id);
}

static void array_member_destroy(void *mb)
{
  array_member_t *m = (array_member_t *)mb;
  ares_buf_destroy(m->buf);
}

static int array_sort_cmp(const void *data1, const void *data2)
{
  const array_member_t *m1 = (const array_member_t *)data1;
  const array_member_t *m2 = (const array_member_t *)data2;
  if (m1->id > m2->id)
    return 1;
  if (m1->id < m2->id)
    return -1;
  return 0;
}

TEST_F(LibraryTest, Array) {
  ares_array_t   *a       = NULL;
  array_member_t *m       = NULL;
  array_member_t  mbuf;
  unsigned int    cnt     = 0;
  unsigned int    removed = 0;
  void           *ptr     = NULL;
  size_t          i;

  a = ares_array_create(sizeof(array_member_t), array_member_destroy);
  EXPECT_NE(nullptr, a);

  /* Try to sort with no elements, should break out */
  EXPECT_EQ(ARES_SUCCESS, ares_array_sort(a, array_sort_cmp));

  /* Add 8 elements */
  for ( ; cnt < 8 ; cnt++) {
    EXPECT_EQ(ARES_SUCCESS, ares_array_insert_last(&ptr, a));
    array_member_init(ptr, cnt+1);
  }

  /* Insert at invalid index */
  EXPECT_NE(ARES_SUCCESS, ares_array_insert_at(&ptr, a, 12345678));

  /* Verify count */
  EXPECT_EQ(cnt, ares_array_len(a));

  /* Remove the first 2 elements */
  EXPECT_EQ(ARES_SUCCESS, ares_array_remove_first(a));
  EXPECT_EQ(ARES_SUCCESS, ares_array_remove_first(a));
  removed += 2;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares_array_len(a));

  /* Verify id of first element */
  m = (array_member_t *)ares_array_first(a);
  EXPECT_NE(nullptr, m);
  EXPECT_EQ(3, m->id);


  /* Add 100 total elements, this should force a shift of memory at some
   * to make sure moves are working */
  for ( ; cnt < 100 ; cnt++) {
    EXPECT_EQ(ARES_SUCCESS, ares_array_insert_last(&ptr, a));
    array_member_init(ptr, cnt+1);
  }

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares_array_len(a));

  /* Remove 2 from the end */
  EXPECT_EQ(ARES_SUCCESS, ares_array_remove_last(a));
  EXPECT_EQ(ARES_SUCCESS, ares_array_remove_last(a));
  removed += 2;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares_array_len(a));

  /* Verify expected id of last member */
  m = (array_member_t *)ares_array_last(a);
  EXPECT_NE(nullptr, m);
  EXPECT_EQ(cnt-2, m->id);

  /* Remove 3 middle members */
  EXPECT_EQ(ARES_SUCCESS, ares_array_remove_at(a, ares_array_len(a)/2));
  EXPECT_EQ(ARES_SUCCESS, ares_array_remove_at(a, ares_array_len(a)/2));
  EXPECT_EQ(ARES_SUCCESS, ares_array_remove_at(a, ares_array_len(a)/2));
  removed += 3;

  /* Verify count */
  EXPECT_EQ(cnt-removed, ares_array_len(a));

  /* Claim a middle member then re-add it at the same position */
  i = ares_array_len(a) / 2;
  EXPECT_EQ(ARES_SUCCESS, ares_array_claim_at(&mbuf, sizeof(mbuf), a, i));
  EXPECT_EQ(ARES_SUCCESS, ares_array_insert_at(&ptr, a, i));
  array_member_init(ptr, mbuf.id);
  array_member_destroy((void *)&mbuf);
  /* Verify count */
  EXPECT_EQ(cnt-removed, ares_array_len(a));

  /* Iterate across the array, make sure each entry is greater than the last and
   * the data in the buffer matches the id in the array */
  unsigned int last_id = 0;
  for (i=0; i<ares_array_len(a); i++) {
    m = (array_member_t *)ares_array_at(a, i);
    EXPECT_NE(nullptr, m);
    EXPECT_GT(m->id, last_id);
    last_id = m->id;

    unsigned int bufval = 0;
    ares_buf_tag(m->buf);
    EXPECT_EQ(ARES_SUCCESS, ares_buf_fetch_be32(m->buf, &bufval));
    ares_buf_tag_rollback(m->buf);
    EXPECT_EQ(bufval, m->id);
  }

  /* add a new element in the middle to the beginning with a high id */
  EXPECT_EQ(ARES_SUCCESS, ares_array_insert_at(&ptr, a, ares_array_len(a)/2));
  array_member_init(ptr, 100000);

  /* Sort the array */
  EXPECT_EQ(ARES_SUCCESS, ares_array_sort(a, array_sort_cmp));

  /* Iterate across the array, make sure each entry is greater than the last and
   * the data in the buffer matches the id in the array */
  last_id = 0;
  for (i=0; i<ares_array_len(a); i++) {
    m = (array_member_t *)ares_array_at(a, i);
    EXPECT_NE(nullptr, m);
    EXPECT_GT(m->id, last_id);
    last_id = m->id;

    unsigned int bufval = 0;
    ares_buf_tag(m->buf);
    EXPECT_EQ(ARES_SUCCESS, ares_buf_fetch_be32(m->buf, &bufval));
    ares_buf_tag_rollback(m->buf);
    EXPECT_EQ(bufval, m->id);
  }

  ares_array_destroy(a);
}

/* Regression: repeatedly claiming the first element drives the internal
 * offset up to the allocation size.  Re-inserting afterwards must still
 * succeed (previously ares_array_insert_at() failed with ARES_EFORMERR
 * because compaction tried to move from an out-of-range source index). */
TEST_F(LibraryTest, ArrayClaimFrontThenReuse) {
  ares_array_t *a = ares_array_create(sizeof(size_t), NULL);
  EXPECT_NE(nullptr, a);

  for (size_t iter = 0; iter < 4; iter++) {
    /* Fill exactly to the minimum allocation (ARES__ARRAY_MIN == 4) so a
     * full front-drain later pushes offset to precisely alloc_cnt. */
    for (size_t i = 0; i < 4; i++) {
      size_t val = iter * 100 + i;
      EXPECT_EQ(ARES_SUCCESS, ares_array_insertdata_last(a, &val));
    }
    EXPECT_EQ((size_t)4, ares_array_len(a));

    /* Drain ALL elements from the front so offset climbs to alloc_cnt (the
     * condition the fix guards); verify copy-out value and FIFO order. */
    for (size_t i = 0; i < 4; i++) {
      size_t out = 0;
      EXPECT_EQ(ARES_SUCCESS, ares_array_claim_at(&out, sizeof(out), a, 0));
      EXPECT_EQ(iter * 100 + i, out);
    }
    EXPECT_EQ((size_t)0, ares_array_len(a));

    /* Array is now empty with offset == alloc_cnt; appending must still
     * work, and the data must be readable back out. */
    size_t *ptr = NULL;
    EXPECT_EQ(ARES_SUCCESS, ares_array_insert_last((void **)&ptr, a));
    EXPECT_NE(nullptr, ptr);
    *ptr = 424242;
    EXPECT_EQ((size_t)424242, *(size_t *)ares_array_at(a, 0));
    EXPECT_EQ(ARES_SUCCESS, ares_array_remove_first(a));
  }

  EXPECT_EQ((size_t)0, ares_array_len(a));
  ares_array_destroy(a);
}

TEST_F(LibraryTest, HtableVpvp) {
  ares_llist_t       *l = NULL;
  ares_htable_vpvp_t *h = NULL;
  ares_llist_node_t  *n = NULL;
  size_t               i;

#define VPVP_TABLE_SIZE 1000

  l = ares_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares_htable_vpvp_create(NULL, ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<VPVP_TABLE_SIZE; i++) {
    void *p = ares_malloc_zero(4);
    EXPECT_NE((void *)NULL, p);
    EXPECT_NE((void *)NULL, ares_llist_insert_last(l, p));
    EXPECT_TRUE(ares_htable_vpvp_insert(h, p, p));
  }

  EXPECT_EQ(VPVP_TABLE_SIZE, ares_llist_len(l));
  EXPECT_EQ(VPVP_TABLE_SIZE, ares_htable_vpvp_num_keys(h));

  n = ares_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares_llist_node_t *next = ares_llist_node_next(n);
    void               *p    = ares_llist_node_val(n);
    EXPECT_NE((void *)NULL, p);
    EXPECT_EQ(p, ares_htable_vpvp_get_direct(h, p));
    EXPECT_TRUE(ares_htable_vpvp_get(h, p, NULL));
    EXPECT_TRUE(ares_htable_vpvp_remove(h, p));
    ares_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares_llist_len(l));
  EXPECT_EQ(0, ares_htable_vpvp_num_keys(h));

  ares_llist_destroy(l);
  ares_htable_vpvp_destroy(h);
}

TEST_F(LibraryTest, BufSplitStr) {
  ares_buf_t  *buf   = NULL;
  char        **strs  = NULL;
  size_t        nstrs = 0;

  buf = ares_buf_create();
  ares_buf_append_str(buf, "string1\nstring2 string3\t   \nstring4");
  ares_buf_split_str(buf, (const unsigned char *)"\n \t", 2, ARES_BUF_SPLIT_TRIM, 0, &strs, &nstrs);
  ares_buf_destroy(buf);

  EXPECT_EQ(4, nstrs);
  EXPECT_TRUE(ares_streq(strs[0], "string1"));
  EXPECT_TRUE(ares_streq(strs[1], "string2"));
  EXPECT_TRUE(ares_streq(strs[2], "string3"));
  EXPECT_TRUE(ares_streq(strs[3], "string4"));
  ares_free_array(strs, nstrs, ares_free);
}

TEST_F(LibraryTest, BufReplace) {
  ares_buf_t  *buf = NULL;
  size_t       i;
  struct {
    const char *input;
    const char *srch;
    const char *rplc;
    const char *output;
  } tests[] = {
    /* Same size */
    { "nameserver_1.2.3.4\nnameserver_2.3.4.5\n", "_", " ", "nameserver 1.2.3.4\nnameserver 2.3.4.5\n" },
    /* Longer */
    { "nameserver_1.2.3.4\nnameserver_2.3.4.5\n", "_", "|||", "nameserver|||1.2.3.4\nnameserver|||2.3.4.5\n" },
    /* Shorter */
    { "nameserver_1.2.3.4\nnameserver_2.3.4.5\n", "_", "", "nameserver1.2.3.4\nnameserver2.3.4.5\n" }
  };
  char        *str = NULL;

  for (i=0; i<sizeof(tests)/sizeof(*tests); i++) {
    buf = ares_buf_create();
    EXPECT_EQ(ARES_SUCCESS, ares_buf_append_str(buf, tests[i].input));
    EXPECT_EQ(ARES_SUCCESS, ares_buf_replace(buf, (const unsigned char *)tests[i].srch, ares_strlen(tests[i].srch), (const unsigned char *)tests[i].rplc, ares_strlen(tests[i].rplc)));
    str = ares_buf_finish_str(buf, NULL);
    EXPECT_STREQ(str, tests[i].output);
    ares_free(str);
  }
}

typedef struct {
  ares_socket_t s;
} test_htable_asvp_t;

TEST_F(LibraryTest, ZeroLengthRawRrKeepsType) {
  ares_dns_record_t *parsed = NULL;
  ares_dns_rr_t     *rr     = NULL;

  /* Hand-crafted minimal DNS response with a zero-length RAW_RR.
   * Header: id=0x1234, QR=1 RD=1 RA=1, QDCOUNT=1, ANCOUNT=1
   * Question: \x07example\x03com\x00, type A (1), class IN (1)
   * Answer:   \xc0\x0c (name ptr), type=0xFF98 (65432), class IN,
   *           TTL=300, RDLENGTH=0 */
  const unsigned char pkt[] = {
    /* Header */
    0x12, 0x34,  /* ID */
    0x81, 0x80,  /* Flags: QR=1, RD=1, RA=1 */
    0x00, 0x01,  /* QDCOUNT=1 */
    0x00, 0x01,  /* ANCOUNT=1 */
    0x00, 0x00,  /* NSCOUNT=0 */
    0x00, 0x00,  /* ARCOUNT=0 */
    /* Question: example.com, type A, class IN */
    0x07, 'e','x','a','m','p','l','e',
    0x03, 'c','o','m',
    0x00,
    0x00, 0x01,  /* QTYPE=A */
    0x00, 0x01,  /* QCLASS=IN */
    /* Answer RR: example.com (compressed), type 65432, class IN, TTL 300 */
    0xc0, 0x0c,  /* Name pointer */
    0xff, 0x98,  /* TYPE=65432 */
    0x00, 0x01,  /* CLASS=IN */
    0x00, 0x00, 0x01, 0x2c,  /* TTL=300 */
    0x00, 0x00   /* RDLENGTH=0 */
  };

  EXPECT_EQ(ARES_SUCCESS,
    ares_dns_parse(pkt, sizeof(pkt), 0, &parsed));
  EXPECT_EQ(1, ares_dns_record_rr_cnt(parsed, ARES_SECTION_ANSWER));
  rr = ares_dns_record_rr_get(parsed, ARES_SECTION_ANSWER, 0);
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, ares_dns_rr_get_type(rr));
  EXPECT_EQ(65432, ares_dns_rr_get_u16(rr, ARES_RR_RAW_RR_TYPE));

  /* Verify zero-length RAW_RR serializes cleanly */
  unsigned char *buf    = NULL;
  size_t         buflen = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(parsed, &buf, &buflen));
  ares_free(buf);

  ares_dns_record_destroy(parsed);
}

TEST_F(LibraryTest, RawRrTypeTostrFromstrRoundtrip) {
  const char         *str;
  ares_dns_rec_type_t qtype = (ares_dns_rec_type_t)0;

  str = ares_dns_rec_type_tostr(ARES_REC_TYPE_RAW_RR);
  EXPECT_NE((const char *)NULL, str);
  EXPECT_TRUE(ares_dns_rec_type_fromstr(&qtype, str));
  EXPECT_EQ(ARES_REC_TYPE_RAW_RR, qtype);
}

TEST_F(LibraryTest, BufReplaceNullBuf) {
  EXPECT_EQ(ARES_EFORMERR,
            ares_buf_replace(NULL,
                             (const unsigned char *)"x", 1,
                             (const unsigned char *)"y", 1));
}

TEST_F(LibraryTest, HtableAsvp) {
  ares_llist_t       *l = NULL;
  ares_htable_asvp_t *h = NULL;
  ares_llist_node_t  *n = NULL;
  size_t               i;

#define ASVP_TABLE_SIZE 1000

  l = ares_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares_htable_asvp_create(ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<ASVP_TABLE_SIZE; i++) {
    test_htable_asvp_t *a = (test_htable_asvp_t *)ares_malloc_zero(sizeof(*a));
    EXPECT_NE((void *)NULL, a);
    a->s = (ares_socket_t)i+1;
    EXPECT_NE((void *)NULL, ares_llist_insert_last(l, a));
    EXPECT_TRUE(ares_htable_asvp_insert(h, a->s, a));
  }

  EXPECT_EQ(ASVP_TABLE_SIZE, ares_llist_len(l));
  EXPECT_EQ(ASVP_TABLE_SIZE, ares_htable_asvp_num_keys(h));

  n = ares_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares_llist_node_t *next = ares_llist_node_next(n);
    test_htable_asvp_t *a    = (test_htable_asvp_t *)ares_llist_node_val(n);
    EXPECT_NE((void *)NULL, a);
    EXPECT_EQ(a, ares_htable_asvp_get_direct(h, a->s));
    EXPECT_TRUE(ares_htable_asvp_get(h, a->s, NULL));
    EXPECT_TRUE(ares_htable_asvp_remove(h, a->s));
    ares_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares_llist_len(l));
  EXPECT_EQ(0, ares_htable_asvp_num_keys(h));

  ares_llist_destroy(l);
  ares_htable_asvp_destroy(h);
}


typedef struct {
  size_t s;
} test_htable_szvp_t;

TEST_F(LibraryTest, HtableSzvp) {
  ares_llist_t       *l = NULL;
  ares_htable_szvp_t *h = NULL;
  ares_llist_node_t  *n = NULL;
  size_t               i;

#define SZVP_TABLE_SIZE 1000

  l = ares_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares_htable_szvp_create(ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<SZVP_TABLE_SIZE; i++) {
    test_htable_szvp_t *s = (test_htable_szvp_t *)ares_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    s->s = i+1;
    EXPECT_NE((void *)NULL, ares_llist_insert_last(l, s));
    EXPECT_TRUE(ares_htable_szvp_insert(h, s->s, s));
  }

  EXPECT_EQ(SZVP_TABLE_SIZE, ares_llist_len(l));
  EXPECT_EQ(SZVP_TABLE_SIZE, ares_htable_szvp_num_keys(h));

  n = ares_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares_llist_node_t *next = ares_llist_node_next(n);
    test_htable_szvp_t *s    = (test_htable_szvp_t *)ares_llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_EQ(s, ares_htable_szvp_get_direct(h, s->s));
    EXPECT_TRUE(ares_htable_szvp_get(h, s->s, NULL));
    EXPECT_TRUE(ares_htable_szvp_remove(h, s->s));
    ares_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares_llist_len(l));
  EXPECT_EQ(0, ares_htable_szvp_num_keys(h));

  ares_llist_destroy(l);
  ares_htable_szvp_destroy(h);
}

typedef struct {
  char s[32];
} test_htable_vpstr_t;

TEST_F(LibraryTest, HtableVpstr) {
  ares_llist_t        *l = NULL;
  ares_htable_vpstr_t *h = NULL;
  ares_llist_node_t   *n = NULL;
  size_t                i;

#define VPSTR_TABLE_SIZE 1000

  l = ares_llist_create(ares_free);
  EXPECT_NE((void *)NULL, l);

  h = ares_htable_vpstr_create();
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<VPSTR_TABLE_SIZE; i++) {
    test_htable_vpstr_t *s = (test_htable_vpstr_t *)ares_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    snprintf(s->s, sizeof(s->s), "%d", (int)i);
    EXPECT_NE((void *)NULL, ares_llist_insert_last(l, s));
    EXPECT_TRUE(ares_htable_vpstr_insert(h, s, s->s));
  }

  EXPECT_EQ(VPSTR_TABLE_SIZE, ares_llist_len(l));
  EXPECT_EQ(VPSTR_TABLE_SIZE, ares_htable_vpstr_num_keys(h));

  n = ares_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares_llist_node_t *next = ares_llist_node_next(n);
    test_htable_vpstr_t *s   = (test_htable_vpstr_t *)ares_llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_STREQ(s->s, ares_htable_vpstr_get_direct(h, s));
    EXPECT_TRUE(ares_htable_vpstr_get(h, s, NULL));
    EXPECT_TRUE(ares_htable_vpstr_remove(h, s));
    ares_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares_llist_len(l));
  EXPECT_EQ(0, ares_htable_vpstr_num_keys(h));

  ares_llist_destroy(l);
  ares_htable_vpstr_destroy(h);
}


typedef struct {
  char s[32];
} test_htable_strvp_t;

TEST_F(LibraryTest, HtableStrvp) {
  ares_llist_t        *l = NULL;
  ares_htable_strvp_t *h = NULL;
  ares_llist_node_t   *n = NULL;
  size_t                i;

#define STRVP_TABLE_SIZE 1000

  l = ares_llist_create(NULL);
  EXPECT_NE((void *)NULL, l);

  h = ares_htable_strvp_create(ares_free);
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<STRVP_TABLE_SIZE; i++) {
    test_htable_strvp_t *s = (test_htable_strvp_t *)ares_malloc_zero(sizeof(*s));
    EXPECT_NE((void *)NULL, s);
    snprintf(s->s, sizeof(s->s), "%d", (int)i);
    EXPECT_NE((void *)NULL, ares_llist_insert_last(l, s));
    EXPECT_TRUE(ares_htable_strvp_insert(h, s->s, s));
  }

  EXPECT_EQ(STRVP_TABLE_SIZE, ares_llist_len(l));
  EXPECT_EQ(STRVP_TABLE_SIZE, ares_htable_strvp_num_keys(h));

  n = ares_llist_node_first(l);
  EXPECT_NE((void *)NULL, n);
  while (n != NULL) {
    ares_llist_node_t *next = ares_llist_node_next(n);
    test_htable_strvp_t *s   = (test_htable_strvp_t *)ares_llist_node_val(n);
    EXPECT_NE((void *)NULL, s);
    EXPECT_EQ(s, ares_htable_strvp_get_direct(h, s->s));
    EXPECT_TRUE(ares_htable_strvp_get(h, s->s, NULL));
    EXPECT_TRUE(ares_htable_strvp_remove(h, s->s));
    ares_llist_node_destroy(n);
    n = next;
  }

  EXPECT_EQ(0, ares_llist_len(l));
  EXPECT_EQ(0, ares_htable_strvp_num_keys(h));

  ares_llist_destroy(l);
  ares_htable_strvp_destroy(h);
}

TEST_F(LibraryTest, HtableDict) {
  ares_htable_dict_t  *h = NULL;
  size_t               i;
  char               **keys;
  size_t               nkeys;

#define DICT_TABLE_SIZE 1000

  h = ares_htable_dict_create();
  EXPECT_NE((void *)NULL, h);

  for (i=0; i<DICT_TABLE_SIZE; i++) {
    char key[32];
    char val[32];
    snprintf(key, sizeof(key), "%d", (int)i);
    snprintf(val, sizeof(val), "val%d", (int)i);
    EXPECT_TRUE(ares_htable_dict_insert(h, key, val));
  }

  EXPECT_EQ(DICT_TABLE_SIZE, ares_htable_dict_num_keys(h));

  keys = ares_htable_dict_keys(h, &nkeys);
  for (i=0; i<nkeys; i++) {
    char val[32];
    snprintf(val, sizeof(val), "val%s", keys[i]);
    EXPECT_STREQ(val, ares_htable_dict_get_direct(h, keys[i]));
    EXPECT_TRUE(ares_htable_dict_get(h, keys[i], NULL));
    EXPECT_TRUE(ares_htable_dict_remove(h, keys[i]));
  }
  ares_free_array(keys, nkeys, ares_free);

  EXPECT_EQ(0, ares_htable_dict_num_keys(h));

  ares_htable_dict_destroy(h);
}

TEST_F(DefaultChannelTest, SaveInvalidChannel) {
  ares_slist_t *saved = channel_->servers;
  channel_->servers = NULL;
  struct ares_options opts;
  int optmask = 0;
  EXPECT_EQ(ARES_ENODATA, ares_save_options(channel_, &opts, &optmask));
  channel_->servers = saved;
}

// Need to put this in own function due to nested lambda bug
// in VS2013. (C2888)
static int configure_socket(ares_socket_t s) {
  // transposed from ares-process, simplified non-block setter.
#if defined(USE_BLOCKING_SOCKETS)
  return 0; /* returns success */
#elif defined(HAVE_FCNTL_O_NONBLOCK)
  /* most recent unix versions */
  int flags;
  flags = fcntl(s, F_GETFL, 0);
  return fcntl(s, F_SETFL, flags | O_NONBLOCK);
#elif defined(HAVE_IOCTL_FIONBIO)
  /* older unix versions */
  int flags = 1;
  return ioctl(s, FIONBIO, &flags);
#elif defined(HAVE_IOCTLSOCKET_FIONBIO)
#ifdef WATT32
  char flags = 1;
#else
  /* Windows */
  unsigned long flags = 1UL;
#endif
  return ioctlsocket(s, (long)FIONBIO, &flags);
#elif defined(HAVE_IOCTLSOCKET_CAMEL_FIONBIO)
  /* Amiga */
  long flags = 1L;
  return IoctlSocket(s, FIONBIO, flags);
#elif defined(HAVE_SETSOCKOPT_SO_NONBLOCK)
  /* BeOS */
  long b = 1L;
  return setsockopt(s, SOL_SOCKET, SO_NONBLOCK, &b, sizeof(b));
#else
#  error "no non-blocking method was found/used/set"
#endif
}

// TODO: This should not really be in this file, but we need ares config
// flags, and here they are available.
const struct ares_socket_functions VirtualizeIO::default_functions = {
  [](int af, int type, int protocol, void *) -> ares_socket_t {
    auto s = ::socket(af, type, protocol);
    if (s == ARES_SOCKET_BAD) {
      return s;
    }
    if (configure_socket(s) != 0) {
      sclose(s);
      return ares_socket_t(-1);
    }
    return s;
  },
  NULL,
  NULL,
  NULL,
  NULL
};


#ifndef CARES_SYMBOL_HIDING
/* ---------------------------------------------------------------------------
 * EBCDIC helpers unit tests (pure logic, no PASE dependency)
 * -------------------------------------------------------------------------*/

/* Spot-check the DNS/hostname charset slots in the EBCDIC->ASCII table
 * that are critical for correct parsing of QtocRtvTCPA output. */
TEST_F(LibraryTest, EbcdicTableDnsCharset) {
  /* Letters a-z (0x81-0x89, 0x91-0x99, 0xA2-0xA9) */
  EXPECT_EQ('a', ares_ebcdic_to_ascii_table[0x81]);
  EXPECT_EQ('i', ares_ebcdic_to_ascii_table[0x89]);
  EXPECT_EQ('j', ares_ebcdic_to_ascii_table[0x91]);
  EXPECT_EQ('r', ares_ebcdic_to_ascii_table[0x99]);
  EXPECT_EQ('s', ares_ebcdic_to_ascii_table[0xA2]);
  EXPECT_EQ('z', ares_ebcdic_to_ascii_table[0xA9]);
  /* Letters A-Z */
  EXPECT_EQ('A', ares_ebcdic_to_ascii_table[0xC1]);
  EXPECT_EQ('I', ares_ebcdic_to_ascii_table[0xC9]);
  EXPECT_EQ('J', ares_ebcdic_to_ascii_table[0xD1]);
  EXPECT_EQ('R', ares_ebcdic_to_ascii_table[0xD9]);
  EXPECT_EQ('S', ares_ebcdic_to_ascii_table[0xE2]);
  EXPECT_EQ('Z', ares_ebcdic_to_ascii_table[0xE9]);
  /* Digits 0-9 */
  EXPECT_EQ('0', ares_ebcdic_to_ascii_table[0xF0]);
  EXPECT_EQ('9', ares_ebcdic_to_ascii_table[0xF9]);
  /* Punctuation used in DNS hostnames and the search-list splitter */
  EXPECT_EQ(' ', ares_ebcdic_to_ascii_table[0x40]); /* space */
  EXPECT_EQ('.', ares_ebcdic_to_ascii_table[0x4B]); /* period */
  EXPECT_EQ('-', ares_ebcdic_to_ascii_table[0x60]); /* hyphen */
  EXPECT_EQ(',', ares_ebcdic_to_ascii_table[0x6B]); /* comma */
  EXPECT_EQ('_', ares_ebcdic_to_ascii_table[0x6D]); /* underscore */
}

/* Test ares_ebcdic_to_ascii_str: single domain, no trailing padding */
TEST_F(LibraryTest, EbcdicToAsciiStrSingleDomain) {
  /* "corp.example.com" in CCSID 37 EBCDIC */
  const char ebcdic[] = {
    '\x83', '\x96', '\x99', '\x97', '\x4b',  /* c o r p . */
    '\x85', '\xa7', '\x81', '\x94', '\x97',  /* e x a m p */
    '\x93', '\x85', '\x4b',                  /* l e .     */
    '\x83', '\x96', '\x94',                  /* c o m     */
    '\0'
  };
  char out[32];
  ares_ebcdic_to_ascii_str(ebcdic, sizeof(ebcdic) - 1, out);
  EXPECT_STREQ("corp.example.com", out);
}

/* Test ares_ebcdic_to_ascii_str: stops at embedded NUL */
TEST_F(LibraryTest, EbcdicToAsciiStrStopsAtNul) {
  /* "ab\0cd" -- should produce "ab" */
  const char ebcdic[] = { '\x81', '\x82', '\0', '\x83', '\x84' };
  char out[10];
  ares_ebcdic_to_ascii_str(ebcdic, sizeof(ebcdic), out);
  EXPECT_STREQ("ab", out);
}

/* Convert a whole EBCDIC, space-separated, blank-padded search_list field and
 * split it, exactly as ares_init_sysconfig_pase() does.  Exercises the table's
 * 0x40 -> ' ' mapping and the whole-field (non-truncating) conversion. */
TEST_F(LibraryTest, EbcdicSearchListSplit) {
  /* "corp.example.com eng.example.com" in CCSID 37, blank(0x40)-padded */
  const char ebcdic_field[48] = {
    '\x83', '\x96', '\x99', '\x97', '\x4b', '\x85', '\xa7', '\x81',
    '\x94', '\x97', '\x93', '\x85', '\x4b', '\x83', '\x96', '\x94',
    '\x40', '\x85', '\x95', '\x87', '\x4b', '\x85', '\xa7', '\x81',
    '\x94', '\x97', '\x93', '\x85', '\x4b', '\x83', '\x96', '\x94',
    '\x40', '\x40', '\x40', '\x40', '\x40', '\x40', '\x40', '\x40',
    '\x40', '\x40', '\x40', '\x40', '\x40', '\x40', '\x40', '\x40'
  };
  char   ascii[sizeof(ebcdic_field) + 1];
  size_t n     = 0;
  char **parts = nullptr;

  ares_ebcdic_to_ascii_str(ebcdic_field, sizeof(ebcdic_field), ascii);
  EXPECT_STREQ("corp.example.com eng.example.com                ", ascii);

  parts = ares_strsplit(ascii, ", ", &n);
  ASSERT_NE(nullptr, parts);
  ASSERT_EQ((size_t)2, n);
  EXPECT_STREQ("corp.example.com", parts[0]);
  EXPECT_STREQ("eng.example.com", parts[1]);
  ares_strsplit_free(parts, n);
}

/* An all-blank (EBCDIC 0x40) search_list field must yield no domains. */
TEST_F(LibraryTest, EbcdicSearchListAllBlanks) {
  char   ebcdic_field[16];
  char   ascii[sizeof(ebcdic_field) + 1];
  size_t n = 99;
  char **parts;

  memset(ebcdic_field, 0x40, sizeof(ebcdic_field));
  ares_ebcdic_to_ascii_str(ebcdic_field, sizeof(ebcdic_field), ascii);
  EXPECT_STREQ("                ", ascii);

  parts = ares_strsplit(ascii, ", ", &n);
  EXPECT_EQ(nullptr, parts);
  EXPECT_EQ((size_t)0, n);
}
#endif /* !CARES_SYMBOL_HIDING */

}  // namespace test
}  // namespace ares
