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

#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseAReplyCnameTtlClamp) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("query.example.com", T_A))
    .add_answer(new DNSCnameRR("query.example.com", -1,
                               "redirect.query.example.com"))
    .add_answer(new DNSARR("redirect.query.example.com", 100,
                           {129, 97, 123, 22}));
  std::vector<byte> data = pkt.data();
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;

  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  ASSERT_NE(nullptr, host);
  EXPECT_EQ(1, count);
  EXPECT_EQ(100, info[0].ttl);
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseUriReplyTtlClamp) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion("example.com", T_URI))
    .add_answer(new DNSUriRR("example.com", -1, 10, 20,
                             "uri.example.com"));
  std::vector<byte> data = pkt.data();
  struct ares_uri_reply *uri = nullptr;

  EXPECT_EQ(ARES_SUCCESS,
            ares_parse_uri_reply(data.data(), (int)data.size(), &uri));
  ASSERT_NE(nullptr, uri);
  EXPECT_EQ(INT_MAX, uri->ttl);
  EXPECT_EQ(nullptr, uri->next);
  ares_free_data(uri);
}

}  // namespace test
}  // namespace ares
