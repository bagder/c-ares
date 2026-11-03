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

#include <sstream>
#include <vector>

namespace ares {
namespace test {

TEST_F(LibraryTest, ParseRootName) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response().set_aa()
    .add_question(new DNSQuestion(".", T_A))
    .add_answer(new DNSARR(".", 100, {0x02, 0x03, 0x04, 0x05}));
  std::vector<byte> data = pkt.data();

  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseIndirectRootName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0xC0, 0x04,  // weird: pointer to a random zero earlier in the message
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0xC0, 0x04,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };

  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}


#if 0 /* We are validating hostnames now, its not clear how this would ever be valid */
TEST_F(LibraryTest, ParseEscapedName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x05, 'a', '\\', 'b', '.', 'c',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x05, 'a', '\\', 'b', '.', 'c',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), data.size(),
                                             &host, info, &count));
  EXPECT_EQ(1, count);
  HostEnt hent(host);
  std::stringstream ss;
  ss << hent;
  // The printable name is expanded with escapes.
  EXPECT_EQ(11, hent.name_.size());
  EXPECT_EQ('a', hent.name_[0]);
  EXPECT_EQ('\\', hent.name_[1]);
  EXPECT_EQ('\\', hent.name_[2]);
  EXPECT_EQ('b', hent.name_[3]);
  EXPECT_EQ('\\', hent.name_[4]);
  EXPECT_EQ('.', hent.name_[5]);
  EXPECT_EQ('c', hent.name_[6]);
  ares_free_hostent(host);
}
#endif

TEST_F(LibraryTest, ParsePartialCompressedName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0x03, 'w', 'w', 'w',
    0xc0, 0x10,  // offset 16
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseFullyCompressedName) {
  std::vector<byte> data = {
    0x12, 0x34,  // qid
    0x84, // response + query + AA + not-TC + not-RD
    0x00, // not-RA + not-Z + not-AD + not-CD + rc=NoError
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x03, 'w', 'w', 'w',
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // Answer 1
    0xc0, 0x0c,  // offset 12
    0x00, 0x01,  // RR type
    0x00, 0x01,  // class IN
    0x01, 0x02, 0x03, 0x04, // TTL
    0x00, 0x04,  // rdata length
    0x02, 0x03, 0x04, 0x05,
  };
  struct hostent *host = nullptr;
  struct ares_addrttl info[2];
  int count = 2;
  EXPECT_EQ(ARES_SUCCESS, ares_parse_a_reply(data.data(), (int)data.size(),
                                             &host, info, &count));
  ASSERT_NE(nullptr, host);
  std::stringstream ss;
  ss << HostEnt(host);
  EXPECT_EQ("{'www.example.com' aliases=[] addrs=[2.3.4.5]}", ss.str());
  ares_free_hostent(host);
}

TEST_F(LibraryTest, ParseMalformedRRCount) {
  ares_dns_record_t *dnsrec = NULL;
  const unsigned char data[] = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x01, 'a',  0x00, 0x00,
    0x01, 0x00, 0x01,
  };

  EXPECT_EQ(ARES_EBADRESP, ares_dns_parse(data, sizeof(data), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

TEST_F(LibraryTest, ParseRejectsOverlongName) {
  // RFC 1035 3.1 limits a name to 255 octets.  A longer name (here built from
  // six 63-octet labels) must be rejected instead of expanded.
  std::vector<byte> data = {
    0x12, 0x34, 0x81, 0x80,
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x01, 'a', 0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
  };
  // Answer name: 6 x 63 label octets + 5 separators = 383 presentation octets
  // (> 255), then root terminator
  for (int i = 0; i < 6; i++) {
    data.push_back(63);
    for (int j = 0; j < 63; j++) {
      data.push_back('a');
    }
  }
  data.push_back(0x00);
  std::vector<byte> tail = {
    0x00, 0x01,              // type A
    0x00, 0x01,              // class IN
    0x00, 0x00, 0x00, 0x00,  // TTL
    0x00, 0x04,              // rdata length
    0x01, 0x02, 0x03, 0x04,
  };
  data.insert(data.end(), tail.begin(), tail.end());

  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_EBADNAME, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

TEST_F(LibraryTest, ParseRejectsOverlongNameViaPointers) {
  // The answer name is one 63-octet label followed by a compression pointer back
  // to the question name (three 63-octet labels and one 61-octet label, 255
  // wire octets, so the question itself is accepted).  Expanded that is
  // 313 payload + 5 length octets + root = 319 wire octets (> 255), so the
  // length has to accumulate across the pointer jump for this to be rejected.
  std::vector<byte> data = {
    0x12, 0x34, 0x81, 0x80,
    0x00, 0x01,  // num questions
    0x00, 0x01,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
  };
  // Question name: labels 63, 63, 63, 61 = 250 payload + 4 length octets +
  // root = 255 wire octets, exactly the limit, so the question is accepted.
  const int qlens[] = {63, 63, 63, 61};
  for (int i = 0; i < 4; i++) {
    data.push_back(static_cast<byte>(qlens[i]));
    for (int j = 0; j < qlens[i]; j++) {
      data.push_back('a');
    }
  }
  data.push_back(0x00);
  std::vector<byte> qtail = {0x00, 0x01, 0x00, 0x01};  // type A, class IN
  data.insert(data.end(), qtail.begin(), qtail.end());
  // Answer name: one 63-octet label, then a pointer to the question name.
  data.push_back(63);
  for (int j = 0; j < 63; j++) {
    data.push_back('a');
  }
  data.push_back(0xc0);
  data.push_back(0x0c);  // -> offset 12, start of question name
  std::vector<byte> tail = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4,
  };
  data.insert(data.end(), tail.begin(), tail.end());
  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_EBADNAME, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

TEST_F(LibraryTest, ParseRejectsPointerChain) {
  // A name built purely from compression pointers adds no label octets, so the
  // length cap alone can never stop it.  A long backward chain of pointers is
  // hidden in the opaque rdata of a raw RR, and a second RR's name points at the
  // top of the chain; walking it must trip the indirection cap and return
  // EBADNAME rather than following every jump.
  std::vector<byte> data = {
    0x12, 0x34, 0x81, 0x80,
    0x00, 0x01,  // num questions
    0x00, 0x02,  // num answer RRs
    0x00, 0x00,  // num authority RRs
    0x00, 0x00,  // num additional RRs
    // Question
    0x01, 'a', 0x00,
    0x00, 0x01,  // type A
    0x00, 0x01,  // class IN
    // RR1: raw RR (unknown type) whose rdata carries the pointer chain
    0x00,        // name = root
    0xff, 0xfe,  // type (unknown -> stored raw, rdata not name-parsed)
    0x00, 0x01,  // class IN
    0x00, 0x00, 0x00, 0x00,  // TTL
  };
  // The chain lives in RR1's rdata, which begins two octets past here (after the
  // rdlength we are about to write), so compute absolute offsets from there.
  const size_t rdata_off = data.size() + 2;
  std::vector<byte> chain;
  chain.push_back(0x00);          // deepest target: root terminator
  size_t prev = rdata_off;        // absolute offset of the root
  size_t top  = prev;
  const int N = 200;              // well past the 128 indirection cap
  for (int i = 0; i < N; i++) {
    size_t here = rdata_off + chain.size();
    chain.push_back(0xc0 | ((prev >> 8) & 0x3f));
    chain.push_back(prev & 0xff);
    top  = here;
    prev = here;
  }
  data.push_back((chain.size() >> 8) & 0xff);  // rdlength
  data.push_back(chain.size() & 0xff);
  data.insert(data.end(), chain.begin(), chain.end());
  // RR2: name = pointer to the top of the chain.
  data.push_back(0xc0 | ((top >> 8) & 0x3f));
  data.push_back(top & 0xff);
  std::vector<byte> tail = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4,
  };
  data.insert(data.end(), tail.begin(), tail.end());

  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_EBADNAME, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

TEST_F(LibraryTest, ParseAcceptsMaxLengthName) {
  // Exactly 255 wire octets: labels 63, 63, 63, 61 = 250 payload + 4
  // length octets + 1 root terminator, which must still be accepted (the
  // bound is "> 255", not ">= 255").
  std::vector<byte> data = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x01, 'a',  0x00, 0x00, 0x01, 0x00, 0x01,
  };
  const int lens[] = {63, 63, 63, 61};
  for (int i = 0; i < 4; i++) {
    data.push_back(static_cast<byte>(lens[i]));
    for (int j = 0; j < lens[i]; j++) {
      data.push_back('a');
    }
  }
  data.push_back(0x00);
  std::vector<byte> tail = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4,
  };
  data.insert(data.end(), tail.begin(), tail.end());
  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_NE(nullptr, dnsrec);
  ares_dns_record_destroy(dnsrec);

  // One label-length octet more (labels 63, 63, 63, 62 = 251 payload +
  // 4 + 1 = 256 wire octets) crosses the RFC 1035 limit and must be
  // rejected.  This case used to be accepted when the length check counted
  // presentation characters (label data plus separators) instead of wire
  // octets, which was 2 octets looser than RFC 1035.
  data.clear();
  data = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x01, 'a',  0x00, 0x00, 0x01, 0x00, 0x01,
  };
  const int lens2[] = {63, 63, 63, 62};
  for (int i = 0; i < 4; i++) {
    data.push_back(static_cast<byte>(lens2[i]));
    for (int j = 0; j < lens2[i]; j++) {
      data.push_back('a');
    }
  }
  data.push_back(0x00);
  data.insert(data.end(), tail.begin(), tail.end());
  dnsrec = NULL;
  EXPECT_EQ(ARES_EBADNAME, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

TEST_F(LibraryTest, ParseRejectsName256) {
  // One octet over: labels 63,63,63,62,1 = 252 + 4 separators = 256 -> reject.
  std::vector<byte> data = {
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x01, 'a',  0x00, 0x00, 0x01, 0x00, 0x01,
  };
  const int lens[] = {63, 63, 63, 62, 1};
  for (int i = 0; i < 5; i++) {
    data.push_back(static_cast<byte>(lens[i]));
    for (int j = 0; j < lens[i]; j++) {
      data.push_back('a');
    }
  }
  data.push_back(0x00);
  std::vector<byte> tail = {
    0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 1, 2, 3, 4,
  };
  data.insert(data.end(), tail.begin(), tail.end());
  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_EBADNAME, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

// A single OPT record in the additional section is valid (EDNS0).
TEST_F(LibraryTest, ParseSingleOpt) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response()
    .add_question(new DNSQuestion("example.com", T_A))
    .add_additional(new DNSOptRR(0, 0, 0, 1280, {}, {}, false));
  std::vector<byte> data = pkt.data();

  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_NE(nullptr, dnsrec);
  ares_dns_record_destroy(dnsrec);
}

// RFC 6891 6.1.1: more than one OPT record in a message is a format error.
TEST_F(LibraryTest, ParseMultipleOptRejected) {
  DNSPacket pkt;
  pkt.set_qid(0x1234).set_response()
    .add_question(new DNSQuestion("example.com", T_A))
    .add_additional(new DNSOptRR(0, 0, 0, 1280, {}, {}, false))
    .add_additional(new DNSOptRR(0, 0, 0, 1280, {}, {}, false));
  std::vector<byte> data = pkt.data();

  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_EBADRESP, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

// RFC 3597 section 4 recommends decompressing these older RR types on read,
// while still prohibiting compression in their outgoing RDATA.
TEST_F(LibraryTest, ParseCompressedLegacyRdataNames)
{
  const struct {
    ares_dns_rec_type_t type;
    ares_dns_rr_key_t   key;
    std::vector<byte>   prefix;
    std::vector<byte>   suffix;
  } cases[] = {
    { ARES_REC_TYPE_SRV,
     ARES_RR_SRV_TARGET,        { 0x00, 0x0a, 0x00, 0x14, 0x00, 0x1e },
     {}       },
    { ARES_REC_TYPE_SIG,
     ARES_RR_SIG_SIGNERS_NAME,  { 0x00, 0x01, 0x08, 0x02,  // type covered, algorithm, labels
        0x00, 0x00, 0x00, 0x3c,  // original TTL
        0x00, 0x00, 0x00, 0x02,  // expiration
        0x00, 0x00, 0x00, 0x01,  // inception
        0x00, 0x01 },
     { 0x01 } }, // key tag, signature
    { ARES_REC_TYPE_NAPTR,
     ARES_RR_NAPTR_REPLACEMENT, { 0x00, 0x64, 0x00, 0x0a,  // order, preference
        0x01, 'S', 0x00, 0x00 },
     {}       }  // flags, services, regexp
  };

  const std::vector<byte> name = { 0x07, 'e',  'x', 'a', 'm', 'p', 'l',
                                   'e',  0x03, 'c', 'o', 'm', 0x00 };

  for (const auto &tc : cases) {
    SCOPED_TRACE(tc.type);
    std::vector<byte> data = {
      0x12, 0x34, 0x84, 0x00,  // qid, response + AA
      0x00, 0x01, 0x00, 0x01,  // one question, one answer
      0x00, 0x00, 0x00, 0x00   // no authority/additional RRs
    };
    data.insert(data.end(), name.begin(), name.end());
    data.insert(
      data.end(),
      { 0x00, static_cast<byte>(tc.type), 0x00, 0x01,  // question type, IN
        0xc0, 0x0c,                                    // owner -> question name
        0x00, static_cast<byte>(tc.type), 0x00, 0x01,  // answer type, IN
        0x00, 0x00, 0x00, 0x3c,                        // TTL
        0x00, static_cast<byte>(tc.prefix.size() + 2 + tc.suffix.size()) });
    std::vector<byte> expected = data;
    expected.back() =
      static_cast<byte>(tc.prefix.size() + name.size() + tc.suffix.size());
    expected.insert(expected.end(), tc.prefix.begin(), tc.prefix.end());
    expected.insert(expected.end(), name.begin(), name.end());
    expected.insert(expected.end(), tc.suffix.begin(), tc.suffix.end());

    data.insert(data.end(), tc.prefix.begin(), tc.prefix.end());
    data.insert(data.end(), { 0xc0, 0x0c });  // RDATA name -> example.com
    data.insert(data.end(), tc.suffix.begin(), tc.suffix.end());

    ares_dns_record_t *dnsrec = nullptr;
    ares_status_t status = ares_dns_parse(data.data(), data.size(), 0, &dnsrec);
    EXPECT_EQ(ARES_SUCCESS, status);
    if (status != ARES_SUCCESS) {
      continue;
    }
    ASSERT_NE(nullptr, dnsrec);
    const ares_dns_rr_t *rr =
      ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, 0);
    EXPECT_STREQ("example.com", ares_dns_rr_get_str(rr, tc.key));

    unsigned char *wire     = nullptr;
    size_t         wire_len = 0;
    EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &wire, &wire_len));
    if (wire != nullptr) {
      EXPECT_EQ(expected, std::vector<byte>(wire, wire + wire_len));
    }
    ares_free_string(wire);
    ares_dns_record_destroy(dnsrec);

    if (tc.type == ARES_REC_TYPE_SRV) {
      struct ares_srv_reply *srv = nullptr;
      EXPECT_EQ(ARES_SUCCESS,
                ares_parse_srv_reply(data.data(), (int)data.size(), &srv));
      EXPECT_NE(nullptr, srv);
      if (srv != nullptr) {
        EXPECT_STREQ("example.com", srv->host);
        EXPECT_EQ(10, srv->priority);
        EXPECT_EQ(20, srv->weight);
        EXPECT_EQ(30, srv->port);
      }
      ares_free_data(srv);
    }

    // Allowing compression must still reject a pointer to its own location.
    size_t name_offset    = data.size() - tc.suffix.size() - 2;
    data[name_offset + 1] = static_cast<byte>(name_offset);
    dnsrec                = nullptr;
    EXPECT_EQ(ARES_EBADNAME,
              ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
    EXPECT_EQ(nullptr, dnsrec);
    ares_dns_record_destroy(dnsrec);
  }
}

// RFC 3597 does not extend receive-side compression to newer types like SVCB.
TEST_F(LibraryTest, ParseSvcbRejectsCompressedTarget) {
  const unsigned char data[] = {
    0x12, 0x34,              // qid
    0x84, 0x00,              // response + AA
    0x00, 0x01,              // qdcount
    0x00, 0x01,              // ancount
    0x00, 0x00,              // nscount
    0x00, 0x00,              // arcount
    // Question (name at offset 0x0c)
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
    0x03, 'c', 'o', 'm',
    0x00,
    0x00, 0x40,              // type SVCB (64)
    0x00, 0x01,              // class IN
    // Answer
    0xc0, 0x0c,              // name -> pointer to example.com
    0x00, 0x40,              // type SVCB
    0x00, 0x01,              // class IN
    0x00, 0x00, 0x00, 0x3c,  // TTL
    0x00, 0x04,              // rdlength
    0x00, 0x01,              // SvcPriority
    0xc0, 0x0c,              // TargetName -> compression pointer (illegal)
  };

  ares_dns_record_t *dnsrec = NULL;
  EXPECT_EQ(ARES_EBADNAME, ares_dns_parse(data, sizeof(data), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}

// Build the presentation form of a wire-legal name whose labels consist
// entirely of a single non-printable byte (0xAA), which the parser renders
// as the 4-character escape "\170".  lens must obey 1..63 and the RFC 1035
// wire limit sum(lens) + lens.size() + 1 <= 255 (payload + one length octet
// per label + root); the presentation form is then 4 * sum(lens) +
// lens.size() - 1 characters, at most 1003 for labels 63+63+63+61.
static std::string EscapedHeavyName(const std::vector<size_t> &lens)
{
  std::string name;
  for (size_t i = 0; i < lens.size(); i++) {
    if (i != 0) {
      name += '.';
    }
    for (size_t j = 0; j < lens[i]; j++) {
      name += "\\170";
    }
  }
  return name;
}

// Append the wire form of the same name (labels of lens[i] 0xAA octets,
// root-terminated).
static void AppendEscapedHeavyWireName(std::vector<byte> *data,
                                       const std::vector<size_t> &lens)
{
  for (size_t n : lens) {
    data->push_back(static_cast<byte>(n));
    for (size_t j = 0; j < n; j++) {
      data->push_back(0xAA);
    }
  }
  data->push_back(0x00);
}

// A parsed, wire-legal name whose presentation form is longer than 511
// characters must survive parse -> write -> parse unchanged.  The writer
// used to copy names through a 512-byte buffer, silently truncating the
// copy; for a compressible field like CNAME the write then failed outright
// (ARES_EFORMERR from the compression bookkeeping).
TEST_F(LibraryTest, WriteRoundTripEscapeHeavyCname)
{
  const std::vector<size_t> lens = {63, 63, 63, 61};  // presentation 1003
  std::vector<byte>         data = {
    0x12, 0x34,              // qid
    0x84, 0x00,              // response + AA
    0x00, 0x01,              // qdcount
    0x00, 0x01,              // ancount
    0x00, 0x00,              // nscount
    0x00, 0x00,              // arcount
    // Question: example.com A IN (name at offset 0x0c)
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, 0x00, 0x01,
    // Answer: owner -> question name
    0xc0, 0x0c,              // CNAME, IN
    0x00, 0x05, 0x00, 0x01,  0x00, 0x00, 0x00, 0x3c,  // TTL 60
  };
  // rdlength: 4 label-length octets + 250 payload octets + root
  data.push_back(0x00);
  data.push_back(static_cast<byte>(4 + 250 + 1));
  AppendEscapedHeavyWireName(&data, lens);

  ares_dns_record_t *dnsrec = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  const ares_dns_rr_t *rr =
    ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, 0);
  const std::string orig = ares_dns_rr_get_str(rr, ARES_RR_CNAME_CNAME);
  ASSERT_EQ(EscapedHeavyName(lens), orig);

  unsigned char *wire     = nullptr;
  size_t         wire_len = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &wire, &wire_len));

  ares_dns_record_t *dnsrec2 = nullptr;
  if (wire != nullptr) {
    EXPECT_EQ(ARES_SUCCESS,
              ares_dns_parse(wire, wire_len, 0, &dnsrec2));
    const ares_dns_rr_t *rr2 =
      ares_dns_record_rr_get_const(dnsrec2, ARES_SECTION_ANSWER, 0);
    EXPECT_EQ(orig, ares_dns_rr_get_str(rr2, ARES_RR_CNAME_CNAME));
  }
  ares_free_string(wire);
  ares_dns_record_destroy(dnsrec);
  ares_dns_record_destroy(dnsrec2);
}

// Same round-trip through a non-compressible field (SVCB TargetName, RFC
// 9460 forbids compression), driven entirely through the public API.  The
// label layout puts the 512-byte truncation point exactly at the end of
// label 3, so the pre-fix writer emitted the truncated prefix as a valid
// name and returned ARES_SUCCESS -- silently altering the record.
TEST_F(LibraryTest, WriteRoundTripEscapeHeavySvcbTargetAPI)
{
  const std::vector<size_t> lens = {50, 50, 27, 63};  // presentation 763
  const std::string         target = EscapedHeavyName(lens);

  ares_dns_record_t *dnsrec = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_dns_record_create(
                            &dnsrec, 0x1234, ARES_FLAG_QR | ARES_FLAG_AA,
                            ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS, ares_dns_record_query_add(
                            dnsrec, "example.com", ARES_REC_TYPE_SVCB,
                            ARES_CLASS_IN));
  ares_dns_rr_t *rr = nullptr;
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_rr_add(&rr, dnsrec, ARES_SECTION_ANSWER,
                                   "example.com", ARES_REC_TYPE_SVCB,
                                   ARES_CLASS_IN, 60));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_rr_set_u16(rr, ARES_RR_SVCB_PRIORITY, 1));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_rr_set_str(rr, ARES_RR_SVCB_TARGET, target.c_str()));

  unsigned char *wire     = nullptr;
  size_t         wire_len = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &wire, &wire_len));

  ares_dns_record_t *dnsrec2 = nullptr;
  if (wire != nullptr) {
    EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(wire, wire_len, 0, &dnsrec2));
    const ares_dns_rr_t *rr2 =
      ares_dns_record_rr_get_const(dnsrec2, ARES_SECTION_ANSWER, 0);
    EXPECT_EQ(target, ares_dns_rr_get_str(rr2, ARES_RR_SVCB_TARGET));
  }
  ares_free_string(wire);
  ares_dns_record_destroy(dnsrec);
  ares_dns_record_destroy(dnsrec2);
}

// Boundary cases for the RFC 1035 255-wire-octet name limit, in escaped
// presentation form.  The longest valid name is four labels of 63+63+63+61
// bytes: 250 payload + 4 length octets + 1 root = 255 wire octets, which
// renders as 4 * 250 + 3 = 1003 presentation characters and must round-trip
// exactly through both a compressible field (CNAME rdata) and a
// non-compressible field (SVCB target).  One payload byte more (labels
// 63+63+63+63 = 257 wire octets, 1011 presentation characters) exceeds the
// RFC limit and must be rejected on both the parse path and the write path.
TEST_F(LibraryTest, WriteRoundTripMaxPresentationName)
{
  const std::vector<size_t> valid_lens   = {63, 63, 63, 61};  // 1003 chars
  const std::vector<size_t> invalid_lens = {63, 63, 63, 63};  // 1011 chars
  const std::string         valid_name   = EscapedHeavyName(valid_lens);
  const std::string         invalid_name = EscapedHeavyName(invalid_lens);
  ASSERT_EQ(1003u, valid_name.size());
  ASSERT_EQ(1011u, invalid_name.size());

  // --- compressible: CNAME rdata via wire parse, valid boundary ---
  std::vector<byte> data = {
    0x12, 0x34, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x05, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
  };
  data.push_back((4 + 250 + 1) >> 8);   // rdlength 255 (4 length octets +
  data.push_back((4 + 250 + 1) & 0xff); // 250 payload + root)
  AppendEscapedHeavyWireName(&data, valid_lens);

  ares_dns_record_t *dnsrec = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  unsigned char *wire     = nullptr;
  size_t         wire_len = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &wire, &wire_len));
  ares_dns_record_t *dnsrec2 = nullptr;
  if (wire != nullptr) {
    EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(wire, wire_len, 0, &dnsrec2));
    const ares_dns_rr_t *rr2 =
      ares_dns_record_rr_get_const(dnsrec2, ARES_SECTION_ANSWER, 0);
    EXPECT_EQ(valid_name, ares_dns_rr_get_str(rr2, ARES_RR_CNAME_CNAME));
  }
  ares_free_string(wire);
  ares_dns_record_destroy(dnsrec);
  ares_dns_record_destroy(dnsrec2);

  // --- non-compressible: SVCB target via the public API, valid boundary ---
  ares_dns_record_t *dnsrec3 = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_dns_record_create(
                            &dnsrec3, 0x1234, ARES_FLAG_QR | ARES_FLAG_AA,
                            ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS, ares_dns_record_query_add(
                            dnsrec3, "example.com", ARES_REC_TYPE_SVCB,
                            ARES_CLASS_IN));
  ares_dns_rr_t *rr = nullptr;
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_rr_add(&rr, dnsrec3, ARES_SECTION_ANSWER,
                                   "example.com", ARES_REC_TYPE_SVCB,
                                   ARES_CLASS_IN, 60));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_rr_set_u16(rr, ARES_RR_SVCB_PRIORITY, 1));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_rr_set_str(rr, ARES_RR_SVCB_TARGET, valid_name.c_str()));

  wire     = nullptr;
  wire_len = 0;
  ares_dns_record_t *dnsrec4 = nullptr;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec3, &wire, &wire_len));
  if (wire != nullptr) {
    EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(wire, wire_len, 0, &dnsrec4));
    const ares_dns_rr_t *rr2 =
      ares_dns_record_rr_get_const(dnsrec4, ARES_SECTION_ANSWER, 0);
    EXPECT_EQ(valid_name, ares_dns_rr_get_str(rr2, ARES_RR_SVCB_TARGET));
  }
  ares_free_string(wire);
  ares_dns_record_destroy(dnsrec3);
  ares_dns_record_destroy(dnsrec4);

  // --- invalid overlength: 257 wire octets rejected by the parser ---
  std::vector<byte> over = {
    0x12, 0x34, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x05, 0x00, 0x01,
    0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
  };
  over.push_back((4 + 252 + 1) >> 8);   // rdlength 257
  over.push_back((4 + 252 + 1) & 0xff);
  AppendEscapedHeavyWireName(&over, invalid_lens);
  ares_dns_record_t *over_rec = nullptr;
  EXPECT_EQ(ARES_EBADNAME,
            ares_dns_parse(over.data(), over.size(), 0, &over_rec));
  EXPECT_EQ(nullptr, over_rec);

  // --- invalid overlength: rejected by the writer via the public API ---
  ares_dns_record_t *over_dnsrec = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_dns_record_create(
                            &over_dnsrec, 0x1234, ARES_FLAG_QR | ARES_FLAG_AA,
                            ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS, ares_dns_record_query_add(
                            over_dnsrec, "example.com", ARES_REC_TYPE_SVCB,
                            ARES_CLASS_IN));
  ares_dns_rr_t *over_rr = nullptr;
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_rr_add(&over_rr, over_dnsrec, ARES_SECTION_ANSWER,
                                   "example.com", ARES_REC_TYPE_SVCB,
                                   ARES_CLASS_IN, 60));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_rr_set_u16(over_rr, ARES_RR_SVCB_PRIORITY, 1));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_rr_set_str(over_rr, ARES_RR_SVCB_TARGET,
                                invalid_name.c_str()));
  unsigned char *over_wire    = nullptr;
  size_t         over_wire_len = 0;
  EXPECT_EQ(ARES_EBADNAME,
            ares_dns_write(over_dnsrec, &over_wire, &over_wire_len));
  ares_free_string(over_wire);
  ares_dns_record_destroy(over_dnsrec);

  // --- beyond the writer's buffer: a 1029-character presentation form can
  // only be a wire-invalid name, and must be rejected by the up-front guard
  // instead of being copied truncated ---
  std::string huge;
  for (size_t i = 0; i < 206; i++) {
    if (i != 0) {
      huge += '.';
    }
    huge += "\\170";
  }
  ASSERT_EQ(1029u, huge.size());
  ares_dns_record_t *huge_dnsrec = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_dns_record_create(
                            &huge_dnsrec, 0x1234, ARES_FLAG_QR | ARES_FLAG_AA,
                            ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ares_dns_rr_t *huge_rr = nullptr;
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_rr_add(&huge_rr, huge_dnsrec, ARES_SECTION_ANSWER,
                                   "example.com", ARES_REC_TYPE_SVCB,
                                   ARES_CLASS_IN, 60));
  ares_dns_rr_set_u16(huge_rr, ARES_RR_SVCB_PRIORITY, 1);
  ares_dns_rr_set_str(huge_rr, ARES_RR_SVCB_TARGET, huge.c_str());
  unsigned char *huge_wire = nullptr;
  size_t         huge_len  = 0;
  EXPECT_EQ(ARES_EBADNAME,
            ares_dns_write(huge_dnsrec, &huge_wire, &huge_len));
  ares_free_string(huge_wire);
  ares_dns_record_destroy(huge_dnsrec);
}

// An escape-heavy name must also remain a compression point.  Question and
// owner names are hostname-validated on write, so escaped label bytes can
// only appear in rdata name fields; two CNAME records carrying the same
// long rdata name must re-encode the second occurrence as a pointer to the
// first, and both must parse back to the same presentation string.
TEST_F(LibraryTest, WriteRoundTripCompressesEscapeHeavyName)
{
  const std::vector<size_t> lens = {63, 63, 63, 61};
  std::vector<byte>         data = {
    0x12, 0x34, 0x84, 0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
    // Question: example.com A IN (name at offset 0x0c)
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, 0x00, 0x01,
  };
  // RR1: owner -> question name, CNAME, rdata = the full escaped name.
  // Offsets: 12 (header) + 13 (qname) + 4 (qtype/qclass) = 29; owner 2 +
  // type/class 4 + ttl 4 + rdlength 2 = 12, so the rdata name lands at 41.
  data.insert(data.end(),
              {0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c});
  data.push_back((4 + 250 + 1) >> 8);
  data.push_back((4 + 250 + 1) & 0xff);
  AppendEscapedHeavyWireName(&data, lens);
  // RR2: owner -> question name, CNAME, rdata = pointer to offset 41.
  data.insert(data.end(),
              {0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c,
               0x00, 0x02, 0xc0, 41});

  ares_dns_record_t *dnsrec = nullptr;
  ASSERT_EQ(ARES_SUCCESS, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  const std::string orig = EscapedHeavyName(lens);
  const ares_dns_rr_t *rr1 =
    ares_dns_record_rr_get_const(dnsrec, ARES_SECTION_ANSWER, 0);
  ASSERT_EQ(orig, ares_dns_rr_get_str(rr1, ARES_RR_CNAME_CNAME));

  unsigned char *wire     = nullptr;
  size_t         wire_len = 0;
  EXPECT_EQ(ARES_SUCCESS, ares_dns_write(dnsrec, &wire, &wire_len));
  if (wire != nullptr) {
    // The second rdata name must be compressed: both label sequences are
    // 255 octets, so an uncompressed message would exceed 500 bytes.
    EXPECT_LT(wire_len, 500u);
    ares_dns_record_t *dnsrec2 = nullptr;
    EXPECT_EQ(ARES_SUCCESS, ares_dns_parse(wire, wire_len, 0, &dnsrec2));
    const ares_dns_rr_t *wrr1 =
      ares_dns_record_rr_get_const(dnsrec2, ARES_SECTION_ANSWER, 0);
    const ares_dns_rr_t *wrr2 =
      ares_dns_record_rr_get_const(dnsrec2, ARES_SECTION_ANSWER, 1);
    EXPECT_EQ(orig, ares_dns_rr_get_str(wrr1, ARES_RR_CNAME_CNAME));
    EXPECT_EQ(orig, ares_dns_rr_get_str(wrr2, ARES_RR_CNAME_CNAME));
    ares_dns_record_destroy(dnsrec2);
  }
  ares_free_string(wire);
  ares_dns_record_destroy(dnsrec);
}

TEST_F(DefaultChannelTest, ParseNameserverUriLinkLocalUninitialized) {
  // Issue #1299: parse_nameserver_uri did not zero-initialize sconfig.
  // When parsing multiple servers in a loop, if a URI server entry has a link-local
  // interface, subsequent URI server entries without one would retain the previous
  // entry's interface.
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_servers_csv(channel_, "dns://[fe80::1%25iface0],dns://2.3.4.5"));
  EXPECT_EQ("2.3.4.5:53", GetNameServers(channel_));
}

}  // namespace test
}  // namespace ares
