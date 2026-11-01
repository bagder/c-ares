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

#include <functional>
#include <limits>
#include <utility>

namespace ares {
namespace test {

namespace {

struct QueueResult {
  int                   calls      = 0;
  ares_status_t         status     = ARES_SUCCESS;
  size_t                timeouts   = 0;
  unsigned short        qid        = 0;
  bool                  has_record = false;
  std::function<void()> on_done;
};

static void QueueCallback(void *arg, ares_status_t status, size_t timeouts,
                          const ares_dns_record_t *dnsrec)
{
  QueueResult          *result  = static_cast<QueueResult *>(arg);
  std::function<void()> on_done = std::move(result->on_done);
  result->calls++;
  result->status     = status;
  result->timeouts   = timeouts;
  result->has_record = dnsrec != nullptr;
  if (dnsrec != nullptr) {
    result->qid = ares_dns_record_get_id(dnsrec);
  }
  if (on_done) {
    on_done();
  }
}

static void QueueLegacyCallback(void *arg, int status, int timeouts,
                                unsigned char *abuf, int alen)
{
  ares_dns_record_t *dnsrec = nullptr;
  if (status == ARES_SUCCESS) {
    EXPECT_GT(alen, 0);
    if (alen > 0) {
      EXPECT_EQ(ARES_SUCCESS,
                ares_dns_parse(abuf, static_cast<size_t>(alen), 0, &dnsrec));
    }
  }
  QueueCallback(arg, static_cast<ares_status_t>(status),
                static_cast<size_t>(timeouts), dnsrec);
  ares_dns_record_destroy(dnsrec);
}

static void ExpectQueueResult(const QueueResult &result, ares_status_t status)
{
  EXPECT_EQ(1, result.calls);
  EXPECT_EQ(status, result.status);
  EXPECT_EQ(size_t{ 0 }, result.timeouts);
  EXPECT_EQ(status == ARES_SUCCESS, result.has_record);
}

static void QueueAnswer(DNSPacket *reply, const char *name)
{
  reply->set_response()
    .set_aa()
    .add_question(new DNSQuestion(name, T_A))
    .add_answer(new DNSARR(name, 60, { 192, 0, 2, 1 }));
}

} /* namespace */

class QueryQueueBase : public MockChannelOptsTest {
public:
  QueryQueueBase(int family, bool tcp, bool cache)
    : MockChannelOptsTest(1, family, tcp, false, FillOptions(&opts_, cache),
                          ARES_OPT_FLAGS | ARES_OPT_QUERY_CACHE |
                            ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES)
  {
  }

protected:
  ares_status_t Start(const char *name, QueueResult *result,
                      unsigned short *qid = nullptr)
  {
    return ares_query_dnsrec(channel_, name, ARES_CLASS_IN, ARES_REC_TYPE_A,
                             QueueCallback, result, qid);
  }

  ares_status_t Send(const char *name, unsigned short supplied_id,
                     unsigned short flags, ares_dns_rec_type_t type,
                     ares_dns_class_t dnsclass, QueueResult *result,
                     unsigned short *qid = nullptr)
  {
    AresDnsRecord query;
    ares_status_t status =
      ares_dns_record_create(&query.dnsrec_, supplied_id, flags,
                             ARES_OPCODE_QUERY, ARES_RCODE_NOERROR);
    if (status != ARES_SUCCESS) {
      return status;
    }
    status = ares_dns_record_query_add(query.dnsrec_, name, type, dnsclass);
    if (status != ARES_SUCCESS) {
      return status;
    }
    return ares_send_dnsrec(channel_, query.dnsrec_, QueueCallback, result,
                            qid);
  }

private:
  static struct ares_options *FillOptions(struct ares_options *opts, bool cache)
  {
    memset(opts, 0, sizeof(*opts));
    /* Disable DNS0x20 to make exact-serialization equality deterministic. */
    opts->flags          = 0;
    opts->qcache_max_ttl = cache ? 600 : 0;
    opts->timeout        = 100;
    opts->tries          = 2;
    return opts;
  }

  struct ares_options opts_;
};

class QueryQueueTest
  : public QueryQueueBase,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  QueryQueueTest() : QueryQueueBase(GetParam().first, GetParam().second, false)
  {
  }
};

class QueryQueueCacheTest
  : public QueryQueueBase,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  QueryQueueCacheTest()
    : QueryQueueBase(GetParam().first, GetParam().second, true)
  {
  }
};

TEST_P(QueryQueueTest, DefaultsAndConfiguration)
{
  size_t      active   = 99;
  size_t      pending  = 99;
  ares_bool_t coalesce = ARES_TRUE;

  EXPECT_EQ(ARES_SUCCESS, ares_get_query_queue_options(channel_, &active,
                                                       &pending, &coalesce));
  EXPECT_EQ(size_t{ 0 }, active);
  EXPECT_EQ(size_t{ 0 }, pending);
  EXPECT_EQ(ARES_FALSE, coalesce);

  EXPECT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 2, 3, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS, ares_get_query_queue_options(channel_, &active,
                                                       &pending, &coalesce));
  EXPECT_EQ(size_t{ 2 }, active);
  EXPECT_EQ(size_t{ 3 }, pending);
  EXPECT_EQ(ARES_TRUE, coalesce);

  EXPECT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 32768, 0, ARES_FALSE));
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 32767, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 0, 0, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 0, 0, ARES_FALSE));
}

TEST_P(QueryQueueTest, RejectsInvalidConfigurationWithoutChangingOptions)
{
  size_t      active   = 0;
  size_t      pending  = 0;
  ares_bool_t coalesce = ARES_FALSE;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 2, 3, ARES_TRUE));
  EXPECT_EQ(ARES_EFORMERR,
            ares_set_query_queue_options(nullptr, 1, 1, ARES_FALSE));
  EXPECT_EQ(ARES_EFORMERR,
            ares_set_query_queue_options(channel_, 0, 1, ARES_TRUE));
  EXPECT_EQ(ARES_EFORMERR,
            ares_set_query_queue_options(channel_, 32769, 0, ARES_FALSE));
  EXPECT_EQ(ARES_EFORMERR,
            ares_set_query_queue_options(channel_, 1, 32768, ARES_FALSE));
  EXPECT_EQ(ARES_EFORMERR,
            ares_set_query_queue_options(
              channel_, (std::numeric_limits<size_t>::max)(), 1, ARES_FALSE));
  EXPECT_EQ(ARES_EFORMERR, ares_get_query_queue_options(nullptr, &active,
                                                        &pending, &coalesce));
  EXPECT_EQ(ARES_EFORMERR, ares_get_query_queue_options(channel_, nullptr,
                                                        &pending, &coalesce));
  EXPECT_EQ(ARES_EFORMERR, ares_get_query_queue_options(channel_, &active,
                                                        nullptr, &coalesce));
  EXPECT_EQ(ARES_EFORMERR,
            ares_get_query_queue_options(channel_, &active, &pending, nullptr));
  EXPECT_EQ(ARES_SUCCESS, ares_get_query_queue_options(channel_, &active,
                                                       &pending, &coalesce));
  EXPECT_EQ(size_t{ 2 }, active);
  EXPECT_EQ(size_t{ 3 }, pending);
  EXPECT_EQ(ARES_TRUE, coalesce);
}

TEST_P(QueryQueueTest, DisabledByDefaultDoesNotMerge)
{
  DNSPacket      reply;
  QueueResult    first;
  QueueResult    second;
  unsigned short first_id  = 0;
  unsigned short second_id = 0;

  QueueAnswer(&reply, "default.example");
  EXPECT_CALL(server_, OnRequest("default.example", T_A))
    .Times(2)
    .WillRepeatedly(SetReply(&server_, &reply));
  EXPECT_EQ(ARES_SUCCESS, Start("default.example", &first, &first_id));
  EXPECT_EQ(ARES_SUCCESS, Start("default.example", &second, &second_id));
  EXPECT_NE(first_id, second_id);
  EXPECT_EQ(size_t{ 2 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(second, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, BusyAndDupCopyOnlyConfiguration)
{
  QueueResult     first;
  QueueResult     follower;
  QueueResult     pending_result;
  ares_channel_t *copy     = nullptr;
  size_t          active   = 0;
  size_t          pending  = 0;
  ares_bool_t     coalesce = ARES_FALSE;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending_result));
  EXPECT_EQ(size_t{ 3 }, ares_queue_active_queries(channel_));
  EXPECT_EQ(ARES_EBUSY,
            ares_set_query_queue_options(channel_, 2, 2, ARES_FALSE));
  EXPECT_EQ(ARES_SUCCESS, ares_dup(&copy, channel_));
  if (copy != nullptr) {
    EXPECT_EQ(ARES_SUCCESS,
              ares_get_query_queue_options(copy, &active, &pending, &coalesce));
    EXPECT_EQ(size_t{ 1 }, active);
    EXPECT_EQ(size_t{ 1 }, pending);
    EXPECT_EQ(ARES_TRUE, coalesce);
    EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(copy));
    EXPECT_EQ(ARES_SUCCESS,
              ares_set_query_queue_options(copy, 0, 0, ARES_FALSE));
    ares_destroy(copy);
  }
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
  ExpectQueueResult(follower, ARES_ECANCELLED);
  ExpectQueueResult(pending_result, ARES_ECANCELLED);
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 0, 0, ARES_FALSE));
}

TEST_P(QueryQueueTest, CannotEnableWhileDefaultLegacyWorkIsOutstanding)
{
  QueueResult first;

  ares_query(channel_, "first.example", C_IN, T_A, QueueLegacyCallback, &first);
  EXPECT_EQ(size_t{ 1 }, ares_queue_active_queries(channel_));
  EXPECT_EQ(ARES_EBUSY,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
  EXPECT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
}

TEST_P(QueryQueueTest, ActiveLimitPromotesPendingInFifoOrder)
{
  DNSPacket           reply1;
  DNSPacket           reply2;
  DNSPacket           reply3;
  QueueResult         first;
  QueueResult         second;
  QueueResult         third;
  unsigned short      first_id  = 0;
  unsigned short      second_id = 0;
  unsigned short      third_id  = 0;
  testing::InSequence sequence;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 2, ARES_FALSE));
  QueueAnswer(&reply1, "first.example");
  QueueAnswer(&reply2, "second.example");
  QueueAnswer(&reply3, "third.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &reply1));
  EXPECT_CALL(server_, OnRequest("second.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_EQ(1, first.calls);
      server_.SetReply(&reply2);
    }));
  EXPECT_CALL(server_, OnRequest("third.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_EQ(1, second.calls);
      server_.SetReply(&reply3);
    }));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first, &first_id));
  EXPECT_EQ(ARES_SUCCESS, Start("second.example", &second, &second_id));
  EXPECT_EQ(ARES_SUCCESS, Start("third.example", &third, &third_id));
  EXPECT_EQ(0, first.calls);
  EXPECT_EQ(0, second.calls);
  EXPECT_EQ(0, third.calls);
  EXPECT_EQ(size_t{ 3 }, ares_queue_active_queries(channel_));
  /* IDs are reserved immediately, including requests not yet on the wire. */
  EXPECT_NE(first_id, second_id);
  EXPECT_NE(first_id, third_id);
  EXPECT_NE(second_id, third_id);
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(second, ARES_SUCCESS);
  ExpectQueueResult(third, ARES_SUCCESS);
  EXPECT_EQ(first_id, first.qid);
  EXPECT_EQ(second_id, second.qid);
  EXPECT_EQ(third_id, third.qid);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, FullQueueRejectsSynchronouslyButAllowsPendingFollower)
{
  DNSPacket      reply1;
  DNSPacket      reply2;
  QueueResult    first;
  QueueResult    pending;
  QueueResult    follower;
  QueueResult    rejected;
  unsigned short pending_id  = 0;
  unsigned short follower_id = 0;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply1, "first.example");
  QueueAnswer(&reply2, "pending.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &reply1));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A))
    .WillOnce(SetReply(&server_, &reply2));
  EXPECT_CALL(server_, OnRequest("rejected.example", T_A)).Times(0);
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending, &pending_id));
  EXPECT_EQ(ARES_EQUEUEFULL, Start("rejected.example", &rejected));
  ExpectQueueResult(rejected, ARES_EQUEUEFULL);
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &follower, &follower_id));
  EXPECT_EQ(pending_id, follower_id);
  EXPECT_EQ(size_t{ 3 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(pending, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_SUCCESS);
  ExpectQueueResult(rejected, ARES_EQUEUEFULL);
}

TEST_P(QueryQueueTest, ActiveAndPendingGroupsEachUseOneWireRequest)
{
  DNSPacket      reply1;
  DNSPacket      reply2;
  QueueResult    first;
  QueueResult    first_follower;
  QueueResult    second;
  QueueResult    second_follower;
  unsigned short ids[4] = { 0, 0, 0, 0 };

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply1, "first.example");
  QueueAnswer(&reply2, "second.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &reply1));
  EXPECT_CALL(server_, OnRequest("second.example", T_A))
    .WillOnce(SetReply(&server_, &reply2));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first, &ids[0]));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first_follower, &ids[1]));
  EXPECT_EQ(ARES_SUCCESS, Start("second.example", &second, &ids[2]));
  EXPECT_EQ(ARES_SUCCESS, Start("second.example", &second_follower, &ids[3]));
  EXPECT_EQ(ids[0], ids[1]);
  EXPECT_EQ(ids[2], ids[3]);
  EXPECT_NE(ids[0], ids[2]);
  EXPECT_EQ(size_t{ 4 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(first_follower, ARES_SUCCESS);
  ExpectQueueResult(second, ARES_SUCCESS);
  ExpectQueueResult(second_follower, ARES_SUCCESS);
  EXPECT_EQ(ids[0], first.qid);
  EXPECT_EQ(ids[1], first_follower.qid);
  EXPECT_EQ(ids[2], second.qid);
  EXPECT_EQ(ids[3], second_follower.qid);
}

TEST_P(QueryQueueTest, CoalescingOnlyWorksWithoutCache)
{
  DNSPacket   reply;
  QueueResult first;
  QueueResult follower;
  QueueResult later;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 0, 0, ARES_TRUE));
  QueueAnswer(&reply, "nocache.example");
  EXPECT_CALL(server_, OnRequest("nocache.example", T_A))
    .Times(2)
    .WillRepeatedly(SetReply(&server_, &reply));
  EXPECT_EQ(ARES_SUCCESS, Start("nocache.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("nocache.example", &follower));
  EXPECT_EQ(size_t{ 2 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_SUCCESS);
  EXPECT_EQ(ARES_SUCCESS, Start("nocache.example", &later));
  EXPECT_EQ(0, later.calls);
  Process(2000);
  ExpectQueueResult(later, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, SendDnsrecIgnoresOnlySuppliedQueryId)
{
  DNSPacket      reply;
  QueueResult    first;
  QueueResult    follower;
  unsigned short first_id    = 0;
  unsigned short follower_id = 0;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 0, ARES_TRUE));
  QueueAnswer(&reply, "raw.example");
  EXPECT_CALL(server_, OnRequest("raw.example", T_A))
    .WillOnce(SetReply(&server_, &reply));
  EXPECT_EQ(ARES_SUCCESS,
            Send("raw.example", 100, ARES_FLAG_RD, ARES_REC_TYPE_A,
                 ARES_CLASS_IN, &first, &first_id));
  EXPECT_EQ(ARES_SUCCESS,
            Send("raw.example", 200, ARES_FLAG_RD, ARES_REC_TYPE_A,
                 ARES_CLASS_IN, &follower, &follower_id));
  EXPECT_EQ(first_id, follower_id);
  EXPECT_EQ(size_t{ 2 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_SUCCESS);
  EXPECT_EQ(first_id, first.qid);
  EXPECT_EQ(follower_id, follower.qid);
}

TEST_P(QueryQueueTest, DifferentQuestionOrFlagsAreNotMerged)
{
  QueueResult first;
  QueueResult different_name;
  QueueResult different_type;
  QueueResult different_class;
  QueueResult different_flags;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 0, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS, Send("raw.example", 100, ARES_FLAG_RD,
                               ARES_REC_TYPE_A, ARES_CLASS_IN, &first));
  EXPECT_EQ(ARES_EQUEUEFULL,
            Send("other.example", 100, ARES_FLAG_RD, ARES_REC_TYPE_A,
                 ARES_CLASS_IN, &different_name));
  EXPECT_EQ(ARES_EQUEUEFULL,
            Send("raw.example", 100, ARES_FLAG_RD, ARES_REC_TYPE_AAAA,
                 ARES_CLASS_IN, &different_type));
  EXPECT_EQ(ARES_EQUEUEFULL,
            Send("raw.example", 100, ARES_FLAG_RD, ARES_REC_TYPE_A,
                 ARES_CLASS_CHAOS, &different_class));
  EXPECT_EQ(ARES_EQUEUEFULL,
            Send("raw.example", 100, ARES_FLAG_RD | ARES_FLAG_CD,
                 ARES_REC_TYPE_A, ARES_CLASS_IN, &different_flags));
  ExpectQueueResult(different_name, ARES_EQUEUEFULL);
  ExpectQueueResult(different_type, ARES_EQUEUEFULL);
  ExpectQueueResult(different_class, ARES_EQUEUEFULL);
  ExpectQueueResult(different_flags, ARES_EQUEUEFULL);
  EXPECT_EQ(size_t{ 1 }, ares_queue_active_queries(channel_));
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
}

TEST_P(QueryQueueTest, DifferentAdditionalRecordDataIsNotMerged)
{
  AresDnsRecord       query;
  ares_dns_rr_t      *opt = nullptr;
  QueueResult         first;
  QueueResult         different;
  const unsigned char short_padding[] = { 0 };
  const unsigned char long_padding[]  = { 0, 0 };

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 0, ARES_TRUE));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_create(&query.dnsrec_, 0, ARES_FLAG_RD,
                                   ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_query_add(query.dnsrec_, "raw.example",
                                      ARES_REC_TYPE_A, ARES_CLASS_IN));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_rr_add(&opt, query.dnsrec_, ARES_SECTION_ADDITIONAL,
                                   "", ARES_REC_TYPE_OPT, ARES_CLASS_IN, 0));
  ASSERT_EQ(ARES_SUCCESS, ares_dns_rr_set_u16(opt, ARES_RR_OPT_UDP_SIZE, 1232));
  ASSERT_EQ(ARES_SUCCESS, ares_dns_rr_set_opt(
                            opt, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_PADDING,
                            short_padding, sizeof(short_padding)));
  EXPECT_EQ(ARES_SUCCESS, ares_send_dnsrec(channel_, query.dnsrec_,
                                           QueueCallback, &first, nullptr));
  EXPECT_EQ(ARES_SUCCESS, ares_dns_rr_set_opt(
                            opt, ARES_RR_OPT_OPTIONS, ARES_OPT_PARAM_PADDING,
                            long_padding, sizeof(long_padding)));
  EXPECT_EQ(ARES_EQUEUEFULL,
            ares_send_dnsrec(channel_, query.dnsrec_, QueueCallback, &different,
                             nullptr));
  ExpectQueueResult(different, ARES_EQUEUEFULL);
  EXPECT_EQ(size_t{ 1 }, ares_queue_active_queries(channel_));
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
}

TEST_P(QueryQueueTest, CancelCompletesEveryLogicalCallerOnce)
{
  QueueResult first;
  QueueResult follower;
  QueueResult pending;
  QueueResult pending_follower;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending_follower));
  ares_cancel(channel_);
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
  ExpectQueueResult(follower, ARES_ECANCELLED);
  ExpectQueueResult(pending, ARES_ECANCELLED);
  ExpectQueueResult(pending_follower, ARES_ECANCELLED);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, CancelDoesNotNeedAnAllocationToDrainWaitingCallers)
{
  QueueResult first;
  QueueResult follower;
  QueueResult pending;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  SetAllocFail(1);
  ares_cancel(channel_);
  ClearFails();
  ExpectQueueResult(first, ARES_ECANCELLED);
  ExpectQueueResult(follower, ARES_ECANCELLED);
  ExpectQueueResult(pending, ARES_ECANCELLED);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, DestroyCompletesEveryLogicalCallerOnce)
{
  QueueResult first;
  QueueResult follower;
  QueueResult pending;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  ares_destroy(channel_);
  channel_ = nullptr;
  ExpectQueueResult(first, ARES_EDESTRUCTION);
  ExpectQueueResult(follower, ARES_EDESTRUCTION);
  ExpectQueueResult(pending, ARES_EDESTRUCTION);
}

TEST_P(QueryQueueTest, ResponseCallbackCancelCancelsUnclaimedFollowers)
{
  DNSPacket   reply;
  QueueResult first;
  QueueResult follower;
  QueueResult pending;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply, "first.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &reply));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A)).Times(0);
  first.on_done = [&]() { ares_cancel(channel_); };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_ECANCELLED);
  ExpectQueueResult(pending, ARES_ECANCELLED);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, CancelCallbackNewRequestSurvivesOuterCancel)
{
  DNSPacket   reply;
  QueueResult first;
  QueueResult follower;
  QueueResult pending;
  QueueResult fresh;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply, "fresh.example");
  /* Cancellation cannot recall an already-sent UDP packet or TCP frame. */
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .Times(testing::AtMost(1))
    .WillRepeatedly(SetReplyData(&server_, std::vector<byte>{}));
  EXPECT_CALL(server_, OnRequest("fresh.example", T_A))
    .WillOnce(SetReply(&server_, &reply));
  first.on_done = [&]() {
    EXPECT_EQ(ARES_ECANCELLED, first.status);
    EXPECT_EQ(ARES_SUCCESS, Start("fresh.example", &fresh));
  };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
  ExpectQueueResult(follower, ARES_ECANCELLED);
  ExpectQueueResult(pending, ARES_ECANCELLED);
  EXPECT_EQ(0, fresh.calls);
  EXPECT_EQ(size_t{ 1 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(fresh, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, NestedCancelAlsoCancelsCallbackCreatedWork)
{
  QueueResult first;
  QueueResult follower;
  QueueResult pending;
  QueueResult fresh;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  first.on_done = [&]() {
    EXPECT_EQ(ARES_SUCCESS, Start("fresh.example", &fresh));
    ares_cancel(channel_);
  };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
  ExpectQueueResult(follower, ARES_ECANCELLED);
  ExpectQueueResult(pending, ARES_ECANCELLED);
  ExpectQueueResult(fresh, ARES_ECANCELLED);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, LegacyCallbacksCanJoinActiveAndPendingGroups)
{
  DNSPacket      reply1;
  DNSPacket      reply2;
  QueueResult    first;
  QueueResult    first_legacy;
  QueueResult    second;
  QueueResult    second_legacy;
  unsigned short first_id  = 0;
  unsigned short second_id = 0;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply1, "first.example");
  QueueAnswer(&reply2, "second.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &reply1));
  EXPECT_CALL(server_, OnRequest("second.example", T_A))
    .WillOnce(SetReply(&server_, &reply2));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first, &first_id));
  ares_query(channel_, "first.example", C_IN, T_A, QueueLegacyCallback,
             &first_legacy);
  ares_query(channel_, "second.example", C_IN, T_A, QueueLegacyCallback,
             &second_legacy);
  EXPECT_EQ(ARES_SUCCESS, Start("second.example", &second, &second_id));
  EXPECT_EQ(size_t{ 4 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(first_legacy, ARES_SUCCESS);
  ExpectQueueResult(second, ARES_SUCCESS);
  ExpectQueueResult(second_legacy, ARES_SUCCESS);
  EXPECT_EQ(first_id, first_legacy.qid);
  EXPECT_EQ(second_id, second_legacy.qid);
}

TEST_P(QueryQueueTest, LegacyCapacityFailureIsSynchronous)
{
  QueueResult first;
  QueueResult rejected;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 0, ARES_FALSE));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  ares_query(channel_, "rejected.example", C_IN, T_A, QueueLegacyCallback,
             &rejected);
  ExpectQueueResult(rejected, ARES_EQUEUEFULL);
  EXPECT_EQ(size_t{ 1 }, ares_queue_active_queries(channel_));
  ares_cancel(channel_);
  ExpectQueueResult(first, ARES_ECANCELLED);
}

TEST_P(QueryQueueCacheTest, CacheAndInflightMergingAreIndependent)
{
  DNSPacket   reply;
  QueueResult first;
  QueueResult follower;
  QueueResult cached;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 0, ARES_TRUE));
  QueueAnswer(&reply, "cached.example");
  EXPECT_CALL(server_, OnRequest("cached.example", T_A))
    .WillOnce(SetReply(&server_, &reply));
  EXPECT_EQ(ARES_SUCCESS, Start("cached.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("cached.example", &follower));
  EXPECT_EQ(size_t{ 2 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_SUCCESS);
  EXPECT_EQ(ARES_SUCCESS, Start("cached.example", &cached));
  ExpectQueueResult(cached, ARES_SUCCESS);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueCacheTest, CacheDoesNotEnableInflightMerging)
{
  DNSPacket   reply;
  QueueResult first;
  QueueResult second;
  QueueResult cached;

  QueueAnswer(&reply, "cached.example");
  EXPECT_CALL(server_, OnRequest("cached.example", T_A))
    .Times(2)
    .WillRepeatedly(SetReply(&server_, &reply));
  EXPECT_EQ(ARES_SUCCESS, Start("cached.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("cached.example", &second));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(second, ARES_SUCCESS);
  EXPECT_EQ(ARES_SUCCESS, Start("cached.example", &cached));
  ExpectQueueResult(cached, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, DisabledSchedulingLeavesIdUntouchedOnImmediateFailure)
{
  AresDnsRecord  query;
  QueueResult    result;
  unsigned short id = 1234;
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_create(&query.dnsrec_, 0, ARES_FLAG_RD,
                                   ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_query_add(query.dnsrec_, "failure.example",
                                      ARES_REC_TYPE_A, ARES_CLASS_IN));
  EXPECT_CALL(server_, OnRequest("failure.example", T_A)).Times(0);
  result.on_done = [&]() {
    EXPECT_EQ(1234, id);
    id = 4321;
  };
  SetAllocFail(1);
  EXPECT_EQ(ARES_ENOMEM, ares_send_dnsrec(channel_, query.dnsrec_,
                                          QueueCallback, &result, &id));
  ClearFails();
  ExpectQueueResult(result, ARES_ENOMEM);
  EXPECT_EQ(4321, id);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueCacheTest, CachedAddrinfoCompletesSynchronouslyWithoutSlots)
{
  DNSPacket                  ipv4;
  DNSPacket                  ipv6;
  QueueResult                seed4;
  QueueResult                seed6;
  QueueResult                cached;
  unsigned short             id = 1234;
  AddrInfoResult             result;
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&ipv4, "cached.example");
  ipv6.set_response()
    .set_aa()
    .add_question(new DNSQuestion("cached.example", T_AAAA))
    .add_answer(new DNSAaaaRR(
      "cached.example", 60,
      { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));
  EXPECT_CALL(server_, OnRequest("cached.example", T_A))
    .WillOnce(SetReply(&server_, &ipv4));
  EXPECT_CALL(server_, OnRequest("cached.example", T_AAAA))
    .WillOnce(SetReply(&server_, &ipv6));
  ASSERT_EQ(ARES_SUCCESS, Start("cached.example", &seed4));
  ASSERT_EQ(ARES_SUCCESS, ares_query_dnsrec(channel_, "cached.example",
                                            ARES_CLASS_IN, ARES_REC_TYPE_AAAA,
                                            QueueCallback, &seed6, nullptr));
  Process(2000);
  ExpectQueueResult(seed4, ARES_SUCCESS);
  ExpectQueueResult(seed6, ARES_SUCCESS);
  cached.on_done = [&]() {
    EXPECT_EQ(1234, id);
    id = 4321;
  };
  EXPECT_EQ(ARES_SUCCESS, Start("cached.example", &cached, &id));
  ExpectQueueResult(cached, ARES_SUCCESS);
  EXPECT_EQ(4321, id);
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags  = ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "cached.example.", nullptr, &hints,
                   AddrInfoCallback, &result);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  ASSERT_NE(nullptr, result.ai_);
  ASSERT_NE(nullptr, result.ai_->nodes);
  ASSERT_NE(nullptr, result.ai_->nodes->ai_next);
  EXPECT_NE(result.ai_->nodes->ai_family,
            result.ai_->nodes->ai_next->ai_family);
  EXPECT_EQ(nullptr, result.ai_->nodes->ai_next->ai_next);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueCacheTest, CachedIpv4DoesNotCancelAnotherCallersIpv6Retry)
{
  DNSPacket                  ipv4;
  DNSPacket                  ipv6;
  QueueResult                seed;
  QueueResult                direct;
  AddrInfoResult             result;
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&ipv4, "dual.example");
  ipv6.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dual.example", T_AAAA))
    .add_answer(new DNSAaaaRR(
      "dual.example", 60,
      { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));
  EXPECT_CALL(server_, OnRequest("dual.example", T_A))
    .WillOnce(SetReply(&server_, &ipv4));
  ASSERT_EQ(ARES_SUCCESS, Start("dual.example", &seed));
  Process(2000);
  ExpectQueueResult(seed, ARES_SUCCESS);
  EXPECT_CALL(server_, OnRequest("dual.example", T_AAAA))
    .WillOnce(SetReplyData(&server_, std::vector<byte>{}))
    .WillOnce(SetReply(&server_, &ipv6));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags  = ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "dual.example.", nullptr, &hints, AddrInfoCallback,
                   &result);
  ASSERT_FALSE(result.done_);
  ASSERT_EQ(ARES_SUCCESS, ares_query_dnsrec(channel_, "dual.example",
                                            ARES_CLASS_IN, ARES_REC_TYPE_AAAA,
                                            QueueCallback, &direct, nullptr));
  EXPECT_EQ(size_t{ 2 }, ares_queue_active_queries(channel_));
  Process(2000);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  ASSERT_NE(nullptr, result.ai_);
  ASSERT_NE(nullptr, result.ai_->nodes);
  ASSERT_NE(nullptr, result.ai_->nodes->ai_next);
  EXPECT_NE(result.ai_->nodes->ai_family,
            result.ai_->nodes->ai_next->ai_family);
  EXPECT_EQ(nullptr, result.ai_->nodes->ai_next->ai_next);
  EXPECT_EQ(1, direct.calls);
  EXPECT_EQ(ARES_SUCCESS, direct.status);
  EXPECT_EQ(size_t{ 1 }, direct.timeouts);
}

TEST_P(QueryQueueTest, MergedAddrinfoCallersContinueThroughSearchDomains)
{
  DNSPacket                  missing;
  DNSPacket                  reply;
  AddrInfoResult             first;
  AddrInfoResult             second;
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };
  testing::InSequence        sequence;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  missing.set_response().set_aa().set_rcode(NXDOMAIN).add_question(
    new DNSQuestion("queue.first.com", T_A));
  QueueAnswer(&reply, "queue.second.org");
  EXPECT_CALL(server_, OnRequest("queue.first.com", T_A))
    .WillOnce(SetReply(&server_, &missing));
  EXPECT_CALL(server_, OnRequest("queue.second.org", T_A))
    .WillOnce(SetReply(&server_, &reply));
  hints.ai_family = AF_INET;
  hints.ai_flags  = ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "queue", nullptr, &hints, AddrInfoCallback,
                   &first);
  ares_getaddrinfo(channel_, "queue", nullptr, &hints, AddrInfoCallback,
                   &second);
  EXPECT_EQ(size_t{ 2 }, ares_queue_active_queries(channel_));
  Process(2000);
  EXPECT_TRUE(first.done_);
  EXPECT_TRUE(second.done_);
  EXPECT_EQ(ARES_SUCCESS, first.status_);
  EXPECT_EQ(ARES_SUCCESS, second.status_);
  for (const auto *result : { &first, &second }) {
    char address[INET_ADDRSTRLEN] = {};
    ASSERT_NE(nullptr, result->ai_);
    ASSERT_NE(nullptr, result->ai_->nodes);
    EXPECT_EQ(AF_INET, result->ai_->nodes->ai_family);
    const auto *addr =
      reinterpret_cast<const sockaddr_in *>(result->ai_->nodes->ai_addr);
    ASSERT_NE(nullptr, ares_inet_ntop(AF_INET, &addr->sin_addr, address,
                                      sizeof(address)));
    EXPECT_STREQ("192.0.2.1", address);
  }
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, RetryKeepsSlotAndLateFollowerCountsOnlyNewTimeouts)
{
  DNSPacket           reply;
  DNSPacket           pending_reply;
  QueueResult         first;
  QueueResult         follower;
  QueueResult         pending;
  unsigned short      first_id    = 0;
  unsigned short      follower_id = 0;
  testing::InSequence sequence;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply, "retry.example");
  QueueAnswer(&pending_reply, "pending.example");
  EXPECT_CALL(server_, OnRequest("retry.example", T_A))
    .WillOnce(SetReplyData(&server_, std::vector<byte>{}));
  EXPECT_CALL(server_, OnRequest("retry.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_EQ(0, pending.calls);
      EXPECT_EQ(ARES_SUCCESS, Start("retry.example", &follower, &follower_id));
      EXPECT_EQ(first_id, follower_id);
      server_.SetReply(&reply);
    }));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_EQ(1, first.calls);
      EXPECT_EQ(1, follower.calls);
      server_.SetReply(&pending_reply);
    }));
  EXPECT_EQ(ARES_SUCCESS, Start("retry.example", &first, &first_id));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  Process(2000);
  EXPECT_EQ(1, first.calls);
  EXPECT_EQ(ARES_SUCCESS, first.status);
  EXPECT_EQ(size_t{ 1 }, first.timeouts);
  ExpectQueueResult(follower, ARES_SUCCESS);
  ExpectQueueResult(pending, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, AllMergedAddrinfoCallersStopUnneededRetries)
{
  DNSPacket                  ipv4;
  DNSPacket                  pending_reply;
  AddrInfoResult             first;
  AddrInfoResult             second;
  QueueResult                pending;
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };
  testing::InSequence        sequence;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 2, ARES_TRUE));
  QueueAnswer(&ipv4, "dual.example");
  QueueAnswer(&pending_reply, "pending.example");
  EXPECT_CALL(server_, OnRequest("dual.example", T_A))
    .WillOnce(SetReply(&server_, &ipv4));
  /* Both logical AAAA callers stop retries after their shared A response.
   * One timeout must finish both callers and release the next FIFO slot. */
  EXPECT_CALL(server_, OnRequest("dual.example", T_AAAA))
    .WillOnce(SetReplyData(&server_, std::vector<byte>{}));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_TRUE(first.done_);
      EXPECT_TRUE(second.done_);
      server_.SetReply(&pending_reply);
    }));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags  = ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "dual.example.", nullptr, &hints, AddrInfoCallback,
                   &first);
  ares_getaddrinfo(channel_, "dual.example.", nullptr, &hints, AddrInfoCallback,
                   &second);
  ASSERT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  EXPECT_EQ(size_t{ 5 }, ares_queue_active_queries(channel_));
  Process(2000);
  for (const auto *result : { &first, &second }) {
    EXPECT_TRUE(result->done_);
    EXPECT_EQ(ARES_SUCCESS, result->status_);
    EXPECT_EQ(1, result->timeouts_);
    ASSERT_NE(nullptr, result->ai_);
    ASSERT_NE(nullptr, result->ai_->nodes);
    EXPECT_EQ(AF_INET, result->ai_->nodes->ai_family);
    EXPECT_EQ(nullptr, result->ai_->nodes->ai_next);
  }
  ExpectQueueResult(pending, ARES_SUCCESS);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, DeferredFailedResponseCanCancelRemainingCallers)
{
  struct Completion {
    AddrInfoResult  result;
    ares_channel_t *channel;
    bool            cancel;
    int             calls = 0;
  };

  DNSPacket                  ipv4;
  DNSPacket                  failed;
  Completion                 first;
  Completion                 second;
  QueueResult                direct;
  QueueResult                pending;
  struct ares_addrinfo_hints hints    = { 0, 0, 0, 0 };
  auto                       callback = [](void *arg, int status, int timeouts,
                     struct ares_addrinfo *ai) {
    auto *completion = static_cast<Completion *>(arg);
    completion->calls++;
    AddrInfoCallback(&completion->result, status, timeouts, ai);
    if (completion->cancel) {
      ares_cancel(completion->channel);
    }
  };

  first.channel = second.channel = channel_;
  first.cancel                   = true;
  second.cancel                  = false;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 2, ARES_TRUE));
  QueueAnswer(&ipv4, "dual.example");
  failed.set_response().set_aa().set_rcode(SERVFAIL).add_question(
    new DNSQuestion("dual.example", T_AAAA));
  EXPECT_CALL(server_, OnRequest("dual.example", T_A))
    .WillOnce(SetReply(&server_, &ipv4));
  /* A retry may already be written before the deferred callbacks flush.
   * The first callback cancels another deferred waiter with its own response
   * copy, the still-retrying direct caller and the pending transaction. */
  EXPECT_CALL(server_, OnRequest("dual.example", T_AAAA))
    .Times(testing::Between(1, 2))
    .WillOnce(SetReply(&server_, &failed))
    .WillRepeatedly(SetReplyData(&server_, std::vector<byte>{}));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A)).Times(0);
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags  = ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "dual.example.", nullptr, &hints, callback,
                   &first);
  ares_getaddrinfo(channel_, "dual.example.", nullptr, &hints, callback,
                   &second);
  ASSERT_EQ(ARES_SUCCESS, ares_query_dnsrec(channel_, "dual.example",
                                            ARES_CLASS_IN, ARES_REC_TYPE_AAAA,
                                            QueueCallback, &direct, nullptr));
  ASSERT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  EXPECT_EQ(size_t{ 6 }, ares_queue_active_queries(channel_));
  Process(2000);
  EXPECT_EQ(1, first.calls);
  EXPECT_TRUE(first.result.done_);
  EXPECT_EQ(ARES_SUCCESS, first.result.status_);
  EXPECT_EQ(0, first.result.timeouts_);
  ASSERT_NE(nullptr, first.result.ai_);
  ASSERT_NE(nullptr, first.result.ai_->nodes);
  EXPECT_EQ(AF_INET, first.result.ai_->nodes->ai_family);
  EXPECT_EQ(nullptr, first.result.ai_->nodes->ai_next);
  EXPECT_EQ(1, second.calls);
  EXPECT_TRUE(second.result.done_);
  EXPECT_EQ(ARES_ECANCELLED, second.result.status_);
  EXPECT_EQ(nullptr, second.result.ai_);
  ExpectQueueResult(direct, ARES_ECANCELLED);
  ExpectQueueResult(pending, ARES_ECANCELLED);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, RetryResponseCopyFailurePreservesAnotherMergedCaller)
{
  DNSPacket                  ipv4;
  DNSPacket                  failed;
  DNSPacket                  ipv6;
  AddrInfoResult             result;
  QueueResult                direct;
  bool                       injected = false;
  struct ares_addrinfo_hints hints    = { 0, 0, 0, 0 };
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&ipv4, "dual.example");
  failed.set_response().set_aa().set_rcode(SERVFAIL).add_question(
    new DNSQuestion("dual.example", T_AAAA));
  ipv6.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dual.example", T_AAAA))
    .add_answer(new DNSAaaaRR(
      "dual.example", 60,
      { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));
  ares_set_server_state_callback(
    channel_,
    [](const char *, ares_bool_t success, int, void *arg) {
      auto *injected = static_cast<bool *>(arg);
      if (!success && !*injected) {
        *injected = true;
        /* The failure notification precedes copying the failed response for
         * a caller that has stopped retries. Fail that copy, not the parser. */
        LibraryTest::SetAllocFail(1);
      }
    },
    &injected);
  EXPECT_CALL(server_, OnRequest("dual.example", T_A))
    .WillOnce(SetReply(&server_, &ipv4));
  EXPECT_CALL(server_, OnRequest("dual.example", T_AAAA))
    .WillOnce(SetReply(&server_, &failed))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_TRUE(result.done_);
      server_.SetReply(&ipv6);
    }));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags  = ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "dual.example.", nullptr, &hints, AddrInfoCallback,
                   &result);
  ASSERT_EQ(ARES_SUCCESS, ares_query_dnsrec(channel_, "dual.example",
                                            ARES_CLASS_IN, ARES_REC_TYPE_AAAA,
                                            QueueCallback, &direct, nullptr));
  Process(2000);
  ClearFails();
  ares_set_server_state_callback(channel_, nullptr, nullptr);
  EXPECT_TRUE(injected);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  ASSERT_NE(nullptr, result.ai_);
  ASSERT_NE(nullptr, result.ai_->nodes);
  EXPECT_EQ(AF_INET, result.ai_->nodes->ai_family);
  EXPECT_EQ(nullptr, result.ai_->nodes->ai_next);
  ExpectQueueResult(direct, ARES_SUCCESS);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, AddrinfoRetryDecisionDoesNotStopAnotherMergedCaller)
{
  DNSPacket                  ipv4;
  DNSPacket                  ipv6;
  AddrInfoResult             result;
  QueueResult                direct;
  struct ares_addrinfo_hints hints = { 0, 0, 0, 0 };

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 2, 1, ARES_TRUE));
  QueueAnswer(&ipv4, "dual.example");
  ipv6.set_response()
    .set_aa()
    .add_question(new DNSQuestion("dual.example", T_AAAA))
    .add_answer(new DNSAaaaRR(
      "dual.example", 60,
      { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }));
  EXPECT_CALL(server_, OnRequest("dual.example", T_A))
    .WillOnce(SetReply(&server_, &ipv4));
  EXPECT_CALL(server_, OnRequest("dual.example", T_AAAA))
    .WillOnce(SetReplyData(&server_, std::vector<byte>{}))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      /* getaddrinfo has its IPv4 result and stopped its own AAAA retries.
       * The direct caller still owns a retry and must receive this response. */
      EXPECT_TRUE(result.done_);
      server_.SetReply(&ipv6);
    }));
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags  = ARES_AI_NOSORT;
  ares_getaddrinfo(channel_, "dual.example.", nullptr, &hints, AddrInfoCallback,
                   &result);
  EXPECT_EQ(ARES_SUCCESS, ares_query_dnsrec(channel_, "dual.example",
                                            ARES_CLASS_IN, ARES_REC_TYPE_AAAA,
                                            QueueCallback, &direct, nullptr));
  EXPECT_EQ(size_t{ 3 }, ares_queue_active_queries(channel_));
  Process(2000);
  EXPECT_TRUE(result.done_);
  EXPECT_EQ(ARES_SUCCESS, result.status_);
  EXPECT_EQ(1, result.timeouts_);
  ASSERT_NE(nullptr, result.ai_);
  ASSERT_NE(nullptr, result.ai_->nodes);
  EXPECT_EQ(AF_INET, result.ai_->nodes->ai_family);
  EXPECT_EQ(nullptr, result.ai_->nodes->ai_next);
  EXPECT_EQ(1, direct.calls);
  EXPECT_EQ(ARES_SUCCESS, direct.status);
  EXPECT_EQ(size_t{ 1 }, direct.timeouts);
}

TEST_P(QueryQueueTest, DestroyDoesNotNeedAnAllocationToDrainWaitingCallers)
{
  QueueResult first;
  QueueResult follower;
  QueueResult pending;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  SetAllocFail(1);
  ares_destroy(channel_);
  channel_ = nullptr;
  ClearFails();
  ExpectQueueResult(first, ARES_EDESTRUCTION);
  ExpectQueueResult(follower, ARES_EDESTRUCTION);
  ExpectQueueResult(pending, ARES_EDESTRUCTION);
}

TEST_P(QueryQueueTest,
       DestroyCallbackCanCancelWithoutChangingDestructionSnapshot)
{
  QueueResult first;
  QueueResult follower;
  QueueResult pending;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  first.on_done = [&]() {
    EXPECT_EQ(ARES_EDESTRUCTION, first.status);
    ares_cancel(channel_);
  };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  ares_destroy(channel_);
  channel_ = nullptr;
  ExpectQueueResult(first, ARES_EDESTRUCTION);
  ExpectQueueResult(follower, ARES_EDESTRUCTION);
  ExpectQueueResult(pending, ARES_EDESTRUCTION);
}

TEST_P(QueryQueueTest, DestroyCallbackRetryIsRefusedWithoutRecursion)
{
  QueueResult first;
  QueueResult retry;
  int         nested_attempts = 0;

  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 0, ARES_TRUE));
  retry.on_done = [&]() {
    EXPECT_EQ(ARES_EDESTRUCTION, retry.status);
    nested_attempts++;
    EXPECT_EQ(ARES_EDESTRUCTION, Start("third.example", &retry));
  };
  first.on_done = [&]() {
    EXPECT_EQ(ARES_EDESTRUCTION, first.status);
    EXPECT_EQ(ARES_EDESTRUCTION, Start("retry.example", &retry));
  };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  ares_destroy(channel_);
  channel_ = nullptr;
  ExpectQueueResult(first, ARES_EDESTRUCTION);
  ExpectQueueResult(retry, ARES_EDESTRUCTION);
  EXPECT_EQ(1, nested_attempts);
}

TEST_P(QueryQueueTest, ConfigurationAllocationFailuresPreserveDefaults)
{
  bool reached_success = false;
  int  failures        = 0;
  for (int nth = 1; nth <= 64; nth++) {
    size_t      active   = 1;
    size_t      pending  = 1;
    ares_bool_t coalesce = ARES_TRUE;
    SetAllocFail(nth);
    ares_status_t status =
      ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE);
    ClearFails();
    if (status == ARES_SUCCESS) {
      reached_success = true;
      break;
    }
    failures++;
    ASSERT_EQ(ARES_ENOMEM, status);
    ASSERT_EQ(ARES_SUCCESS, ares_get_query_queue_options(channel_, &active,
                                                         &pending, &coalesce));
    EXPECT_EQ(size_t{ 0 }, active);
    EXPECT_EQ(size_t{ 0 }, pending);
    EXPECT_EQ(ARES_FALSE, coalesce);
  }
  EXPECT_TRUE(reached_success);
  EXPECT_GT(failures, 0);
}

TEST_P(QueryQueueTest, PendingAdmissionAllocationFailuresPreserveExistingWork)
{
  QueueResult   first;
  AresDnsRecord request;
  bool          reached_success = false;
  int           failures        = 0;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  ASSERT_EQ(ARES_SUCCESS, Start("first.example", &first));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_create(&request.dnsrec_, 0, ARES_FLAG_RD,
                                   ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_query_add(request.dnsrec_, "pending.example",
                                      ARES_REC_TYPE_A, ARES_CLASS_IN));
  for (int nth = 1; nth <= 64; nth++) {
    QueueResult pending;
    SetAllocFail(nth);
    ares_status_t status = ares_send_dnsrec(channel_, request.dnsrec_,
                                            QueueCallback, &pending, nullptr);
    ClearFails();
    if (status == ARES_SUCCESS) {
      reached_success = true;
      EXPECT_EQ(0, pending.calls);
      ares_cancel(channel_);
      ExpectQueueResult(pending, ARES_ECANCELLED);
      break;
    }
    failures++;
    ASSERT_EQ(ARES_ENOMEM, status);
    ExpectQueueResult(pending, ARES_ENOMEM);
    EXPECT_EQ(0, first.calls);
    EXPECT_EQ(size_t{ 1 }, ares_queue_active_queries(channel_));
  }
  EXPECT_TRUE(reached_success);
  EXPECT_GT(failures, 0);
  if (!reached_success) {
    ares_cancel(channel_);
  }
  ExpectQueueResult(first, ARES_ECANCELLED);
}

TEST_P(QueryQueueTest, FollowerAllocationFailuresPreserveOriginalCaller)
{
  QueueResult   first;
  AresDnsRecord request;
  bool          reached_success = false;
  int           failures        = 0;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 0, ARES_TRUE));
  ASSERT_EQ(ARES_SUCCESS, Start("first.example", &first));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_create(&request.dnsrec_, 0, ARES_FLAG_RD,
                                   ARES_OPCODE_QUERY, ARES_RCODE_NOERROR));
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_record_query_add(request.dnsrec_, "first.example",
                                      ARES_REC_TYPE_A, ARES_CLASS_IN));
  for (int nth = 1; nth <= 64; nth++) {
    QueueResult follower;
    SetAllocFail(nth);
    ares_status_t status = ares_send_dnsrec(channel_, request.dnsrec_,
                                            QueueCallback, &follower, nullptr);
    ClearFails();
    if (status == ARES_SUCCESS) {
      reached_success = true;
      EXPECT_EQ(0, follower.calls);
      ares_cancel(channel_);
      ExpectQueueResult(follower, ARES_ECANCELLED);
      break;
    }
    failures++;
    ASSERT_EQ(ARES_ENOMEM, status);
    ExpectQueueResult(follower, ARES_ENOMEM);
    EXPECT_EQ(0, first.calls);
    EXPECT_EQ(size_t{ 1 }, ares_queue_active_queries(channel_));
  }
  EXPECT_TRUE(reached_success);
  EXPECT_GT(failures, 0);
  if (!reached_success) {
    ares_cancel(channel_);
  }
  ExpectQueueResult(first, ARES_ECANCELLED);
}

TEST_P(QueryQueueTest, TwoActiveSlotsPromoteOnlyAfterAnActiveCompletion)
{
  DNSPacket           first_reply;
  DNSPacket           second_reply;
  DNSPacket           third_reply;
  QueueResult         first;
  QueueResult         second;
  QueueResult         third;
  testing::InSequence sequence;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 2, 1, ARES_TRUE));
  QueueAnswer(&first_reply, "first.example");
  QueueAnswer(&second_reply, "second.example");
  QueueAnswer(&third_reply, "third.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReplyData(&server_, std::vector<byte>{}));
  EXPECT_CALL(server_, OnRequest("second.example", T_A))
    .WillOnce(SetReply(&server_, &second_reply));
  EXPECT_CALL(server_, OnRequest("third.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_EQ(0, first.calls);
      EXPECT_EQ(1, second.calls);
      server_.SetReply(&third_reply);
    }));
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &first_reply));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("second.example", &second));
  EXPECT_EQ(ARES_SUCCESS, Start("third.example", &third));
  Process(2000);
  EXPECT_EQ(1, first.calls);
  EXPECT_EQ(ARES_SUCCESS, first.status);
  EXPECT_EQ(size_t{ 1 }, first.timeouts);
  ExpectQueueResult(second, ARES_SUCCESS);
  ExpectQueueResult(third, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, ExhaustedRetriesReleaseSlotForPendingTransaction)
{
  DNSPacket   reply;
  QueueResult first;
  QueueResult pending;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply, "pending.example");
  EXPECT_CALL(server_, OnRequest("timeout.example", T_A))
    .Times(2)
    .WillRepeatedly(SetReplyData(&server_, std::vector<byte>{}));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_EQ(1, first.calls);
      EXPECT_EQ(ARES_ETIMEOUT, first.status);
      server_.SetReply(&reply);
    }));
  EXPECT_EQ(ARES_SUCCESS, Start("timeout.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  Process(3000);
  EXPECT_EQ(1, first.calls);
  EXPECT_EQ(ARES_ETIMEOUT, first.status);
  EXPECT_EQ(size_t{ 2 }, first.timeouts);
  ExpectQueueResult(pending, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, PromotionAllocationFailureCanCancelReentrantly)
{
  DNSPacket first_reply;
  DNSPacket promoted_reply;
  DNSPacket pending_reply;
  bool      reached_success = false;
  int       failures        = 0;
  QueueAnswer(&first_reply, "first.example");
  QueueAnswer(&promoted_reply, "promoted.example");
  QueueAnswer(&pending_reply, "pending.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillRepeatedly(SetReply(&server_, &first_reply));
  EXPECT_CALL(server_, OnRequest("promoted.example", T_A))
    .Times(testing::AnyNumber())
    .WillRepeatedly(SetReply(&server_, &promoted_reply));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A))
    .Times(testing::AnyNumber())
    .WillRepeatedly(SetReply(&server_, &pending_reply));
  for (int nth = 1; nth <= 64; nth++) {
    SCOPED_TRACE(nth);
    QueueResult first;
    QueueResult promoted;
    QueueResult follower;
    QueueResult pending;
    ASSERT_EQ(ARES_SUCCESS,
              ares_set_query_queue_options(channel_, 1, 2, ARES_TRUE));
    first.on_done    = [&]() { SetAllocFail(nth); };
    promoted.on_done = [&]() {
      if (promoted.status == ARES_ENOMEM) {
        ClearFails();
        ares_cancel(channel_);
      }
    };
    ASSERT_EQ(ARES_SUCCESS, Start("first.example", &first));
    ASSERT_EQ(ARES_SUCCESS, Start("promoted.example", &promoted));
    ASSERT_EQ(ARES_SUCCESS, Start("promoted.example", &follower));
    ASSERT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
    /* End injection once the promoted transport is admitted, so later
     * response processing does not consume an unrelated allocation failure. */
    ares_set_query_enqueue_cb(
      channel_, [](void *) { LibraryTest::ClearFails(); }, nullptr);
    Process(2000);
    ClearFails();
    ares_set_query_enqueue_cb(channel_, nullptr, nullptr);
    /* A send can precede a later allocation failure. Drain any such mock
     * packet before the next iteration without creating another query. */
    for (auto fd : server_.fds()) {
      fd_set         readers;
      struct timeval timeout = { 0, 0 };
      FD_ZERO(&readers);
      FD_SET(fd, &readers);
      if (select(static_cast<int>(fd) + 1, &readers, nullptr, nullptr,
                 &timeout) > 0) {
        server_.ProcessFD(fd);
      }
    }
    ExpectQueueResult(first, ARES_SUCCESS);
    EXPECT_EQ(1, promoted.calls);
    if (promoted.status == ARES_SUCCESS) {
      ExpectQueueResult(follower, ARES_SUCCESS);
      ExpectQueueResult(pending, ARES_SUCCESS);
      reached_success = true;
      break;
    }
    ExpectQueueResult(promoted, ARES_ENOMEM);
    ExpectQueueResult(follower, ARES_ECANCELLED);
    ExpectQueueResult(pending, ARES_ECANCELLED);
    EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
    failures++;
  }
  EXPECT_TRUE(reached_success);
  EXPECT_GT(failures, 0);
}

TEST_P(QueryQueueTest, PromotionAllocationFailureDoesNotStrandLaterWork)
{
  DNSPacket   first_reply;
  DNSPacket   third_reply;
  QueueResult first;
  QueueResult second;
  QueueResult third;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 2, ARES_TRUE));
  QueueAnswer(&first_reply, "first.example");
  QueueAnswer(&third_reply, "third.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &first_reply));
  EXPECT_CALL(server_, OnRequest("second.example", T_A)).Times(0);
  EXPECT_CALL(server_, OnRequest("third.example", T_A))
    .WillOnce(SetReply(&server_, &third_reply));
  first.on_done = [&]() { SetAllocFail(1); };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("second.example", &second));
  EXPECT_EQ(ARES_SUCCESS, Start("third.example", &third));
  Process(2000);
  ClearFails();
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(second, ARES_ENOMEM);
  ExpectQueueResult(third, ARES_SUCCESS);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

TEST_P(QueryQueueTest, UdpFallbackRetainsSharedTransactionAndActiveSlot)
{
  DNSPacket           truncated;
  DNSPacket           reply;
  DNSPacket           pending_reply;
  QueueResult         first;
  QueueResult         follower;
  QueueResult         pending;
  testing::InSequence sequence;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  truncated.set_response().set_tc().add_question(
    new DNSQuestion("large.example", T_A));
  QueueAnswer(&reply, "large.example");
  QueueAnswer(&pending_reply, "pending.example");
  if (!GetParam().second) {
    EXPECT_CALL(server_, OnRequest("large.example", T_A))
      .WillOnce(SetReply(&server_, &truncated));
  }
  EXPECT_CALL(server_, OnRequest("large.example", T_A))
    .WillOnce(SetReply(&server_, &reply));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A))
    .WillOnce(testing::InvokeWithoutArgs([&]() {
      EXPECT_EQ(1, first.calls);
      EXPECT_EQ(1, follower.calls);
      server_.SetReply(&pending_reply);
    }));
  EXPECT_EQ(ARES_SUCCESS, Start("large.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("large.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_SUCCESS);
  ExpectQueueResult(pending, ARES_SUCCESS);
}

TEST_P(QueryQueueTest, RemovingAllServersCompletesActiveAndPendingWork)
{
  QueueResult first;
  QueueResult follower;
  QueueResult pending;
  QueueResult rejected;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  first.on_done = [&]() {
    EXPECT_EQ(ARES_EBUSY,
              ares_set_query_queue_options(channel_, 2, 0, ARES_TRUE));
  };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  EXPECT_EQ(ARES_SUCCESS, ares_set_servers_ports(channel_, nullptr));
  EXPECT_EQ(1, first.calls);
  EXPECT_EQ(1, follower.calls);
  EXPECT_NE(ARES_SUCCESS, first.status);
  EXPECT_EQ(first.status, follower.status);
  ExpectQueueResult(pending, ARES_ENOSERVER);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
  EXPECT_EQ(ARES_ENOSERVER, Start("new.example", &rejected));
  ExpectQueueResult(rejected, ARES_ENOSERVER);
}

class QueryQueueMultiTest
  : public MockChannelOptsTest,
    public ::testing::WithParamInterface<std::pair<int, bool>> {
public:
  QueryQueueMultiTest()
    : MockChannelOptsTest(
        2, GetParam().first, GetParam().second, false, FillOptions(&opts_),
        ARES_OPT_FLAGS | ARES_OPT_QUERY_CACHE | ARES_OPT_TIMEOUTMS |
          ARES_OPT_TRIES | ARES_OPT_SERVER_FAILOVER | ARES_OPT_NOROTATE)
  {
  }

protected:
  ares_status_t Start(const char *name, QueueResult *result,
                      unsigned short *qid = nullptr)
  {
    return ares_query_dnsrec(channel_, name, ARES_CLASS_IN, ARES_REC_TYPE_A,
                             QueueCallback, result, qid);
  }

  void FillServer(size_t index, struct ares_addr_port_node *node)
  {
    *node          = {};
    node->family   = GetParam().first;
    node->udp_port = servers_[index]->udpport();
    node->tcp_port = servers_[index]->tcpport();
    if (node->family == AF_INET) {
      ares_inet_pton(AF_INET, "127.0.0.1", &node->addr.addr4);
    } else {
      ares_inet_pton(AF_INET6, "::1", &node->addr.addr6);
    }
  }

  int SelectServer(size_t index)
  {
    struct ares_addr_port_node node;
    FillServer(index, &node);
    return ares_set_servers_ports(channel_, &node);
  }

private:
  static struct ares_options *FillOptions(struct ares_options *opts)
  {
    memset(opts, 0, sizeof(*opts));
    opts->timeout                           = 100;
    opts->tries                             = 2;
    opts->server_failover_opts.retry_chance = 1;
    opts->server_failover_opts.retry_delay  = 1;
    return opts;
  }
  struct ares_options opts_;
};

TEST_P(QueryQueueMultiTest, ServerUpdateAllocationFailuresReleasePromotionHold)
{
  bool succeeded = false;
  int  failures  = 0;
  for (int nth = 1; nth <= 32; nth++) {
    SCOPED_TRACE(nth);
    DNSPacket                  first_reply;
    DNSPacket                  pending_reply;
    QueueResult                first;
    QueueResult                pending;
    struct ares_addr_port_node nodes[2];
    ASSERT_EQ(ARES_SUCCESS, SelectServer(0));
    ASSERT_EQ(ARES_SUCCESS,
              ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
    FillServer(0, &nodes[0]);
    FillServer(1, &nodes[1]);
    nodes[0].next = &nodes[1];
    QueueAnswer(&first_reply, "first.example");
    QueueAnswer(&pending_reply, "pending.example");
    EXPECT_CALL(*servers_[0], OnRequest("first.example", T_A))
      .WillOnce(SetReply(servers_[0].get(), &first_reply));
    EXPECT_CALL(*servers_[0], OnRequest("pending.example", T_A))
      .WillOnce(SetReply(servers_[0].get(), &pending_reply));
    ASSERT_EQ(ARES_SUCCESS, Start("first.example", &first));
    ASSERT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
    SetAllocFail(nth);
    int status = ares_set_servers_ports(channel_, &nodes[0]);
    ClearFails();
    EXPECT_TRUE(status == ARES_SUCCESS || status == ARES_ENOMEM);
    EXPECT_EQ(size_t{ 2 }, ares_queue_active_queries(channel_));
    Process(2000);
    ExpectQueueResult(first, ARES_SUCCESS);
    ExpectQueueResult(pending, ARES_SUCCESS);
    EXPECT_EQ(ARES_SUCCESS,
              ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
    ASSERT_TRUE(testing::Mock::VerifyAndClearExpectations(servers_[0].get()));
    if (status == ARES_SUCCESS) {
      succeeded = true;
      break;
    }
    failures++;
  }
  EXPECT_TRUE(succeeded);
  EXPECT_GE(failures, 6);
}

TEST_P(QueryQueueMultiTest, RoutingChangeSeparatesPendingMergeGenerations)
{
  DNSPacket      first_reply;
  DNSPacket      pending_reply;
  QueueResult    first;
  QueueResult    old_pending;
  QueueResult    new_pending;
  unsigned short old_id = 0;
  unsigned short new_id = 0;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 2, ARES_TRUE));
  QueueAnswer(&first_reply, "first.example");
  QueueAnswer(&pending_reply, "pending.example");
  EXPECT_CALL(*servers_[0], OnRequest("first.example", T_A))
    .Times(testing::AtMost(1))
    .WillRepeatedly(SetReplyData(servers_[0].get(), std::vector<byte>{}));
  EXPECT_CALL(*servers_[0], OnRequest("pending.example", T_A)).Times(0);
  EXPECT_CALL(*servers_[1], OnRequest("first.example", T_A))
    .WillOnce(SetReply(servers_[1].get(), &first_reply));
  EXPECT_CALL(*servers_[1], OnRequest("pending.example", T_A))
    .Times(2)
    .WillRepeatedly(SetReply(servers_[1].get(), &pending_reply));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &old_pending, &old_id));
  ASSERT_EQ(ARES_SUCCESS, SelectServer(1));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &new_pending, &new_id));
  EXPECT_NE(old_id, new_id);
  Process(2000);
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(old_pending, ARES_SUCCESS);
  ExpectQueueResult(new_pending, ARES_SUCCESS);
}

TEST_P(QueryQueueMultiTest, RecoveryProbeRunsWhileUserQueueHasPendingWork)
{
  DNSPacket   failed;
  DNSPacket   seed_reply;
  DNSPacket   limited_reply;
  DNSPacket   pending_reply;
  QueueResult seed;
  QueueResult limited;
  QueueResult pending;
  failed.set_response().set_aa().set_rcode(SERVFAIL).add_question(
    new DNSQuestion("seed.example", T_A));
  QueueAnswer(&seed_reply, "seed.example");
  QueueAnswer(&limited_reply, "limited.example");
  QueueAnswer(&pending_reply, "pending.example");
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  EXPECT_CALL(*servers_[0], OnRequest("seed.example", T_A))
    .WillOnce(SetReply(servers_[0].get(), &failed));
  EXPECT_CALL(*servers_[1], OnRequest("seed.example", T_A))
    .WillOnce(SetReply(servers_[1].get(), &seed_reply));
  EXPECT_EQ(ARES_SUCCESS, Start("seed.example", &seed));
  Process(2000);
  ExpectQueueResult(seed, ARES_SUCCESS);
  ares_sleep_time(10);
  EXPECT_CALL(*servers_[0], OnRequest("limited.example", T_A))
    .WillOnce(SetReply(servers_[0].get(), &limited_reply));
  EXPECT_CALL(*servers_[1], OnRequest("limited.example", T_A))
    .WillOnce(SetReply(servers_[1].get(), &limited_reply));
  EXPECT_CALL(*servers_[0], OnRequest("pending.example", T_A))
    .Times(testing::AtMost(1))
    .WillRepeatedly(SetReply(servers_[0].get(), &pending_reply));
  EXPECT_CALL(*servers_[1], OnRequest("pending.example", T_A))
    .Times(testing::AtMost(1))
    .WillRepeatedly(SetReply(servers_[1].get(), &pending_reply));
  EXPECT_EQ(ARES_SUCCESS, Start("limited.example", &limited));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  EXPECT_EQ(size_t{ 3 }, ares_queue_active_queries(channel_));
  Process(2000);
  ExpectQueueResult(limited, ARES_SUCCESS);
  ExpectQueueResult(pending, ARES_SUCCESS);
  EXPECT_EQ(size_t{ 0 }, ares_queue_active_queries(channel_));
}

#ifdef CARES_THREADS
class QueryQueueEventTest
  : public MockEventThreadOptsTest,
    public ::testing::WithParamInterface<std::tuple<ares_evsys_t, int, bool>> {
public:
  QueryQueueEventTest()
    : MockEventThreadOptsTest(1, std::get<0>(GetParam()),
                              std::get<1>(GetParam()), std::get<2>(GetParam()),
                              FillOptions(&opts_),
                              ARES_OPT_FLAGS | ARES_OPT_QUERY_CACHE)
  {
  }

protected:
  ares_status_t Start(const char *name, QueueResult *result)
  {
    return ares_query_dnsrec(channel_, name, ARES_CLASS_IN, ARES_REC_TYPE_A,
                             QueueCallback, result, nullptr);
  }

private:
  static struct ares_options *FillOptions(struct ares_options *opts)
  {
    memset(opts, 0, sizeof(*opts));
    return opts;
  }
  struct ares_options opts_;
};

TEST_P(QueryQueueEventTest, WakeupAndWaitEmptyIncludePendingAndMergedCallers)
{
  DNSPacket           first_reply;
  DNSPacket           pending_reply;
  QueueResult         first;
  QueueResult         follower;
  QueueResult         pending;
  testing::InSequence sequence;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&first_reply, "first.example");
  QueueAnswer(&pending_reply, "pending.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &first_reply));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A))
    .WillOnce(SetReply(&server_, &pending_reply));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  EXPECT_EQ(size_t{ 3 }, ares_queue_active_queries(channel_));
  EXPECT_EQ(ARES_ETIMEOUT, ares_queue_wait_empty(channel_, 0));
  Process(2000);
  EXPECT_EQ(ARES_SUCCESS, ares_queue_wait_empty(channel_, 100));
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_SUCCESS);
  ExpectQueueResult(pending, ARES_SUCCESS);
}

TEST_P(QueryQueueEventTest, CompletionCallbackCancellationDrainsLogicalWaiters)
{
  DNSPacket   reply;
  QueueResult first;
  QueueResult follower;
  QueueResult pending;
  ASSERT_EQ(ARES_SUCCESS,
            ares_set_query_queue_options(channel_, 1, 1, ARES_TRUE));
  QueueAnswer(&reply, "first.example");
  EXPECT_CALL(server_, OnRequest("first.example", T_A))
    .WillOnce(SetReply(&server_, &reply));
  EXPECT_CALL(server_, OnRequest("pending.example", T_A)).Times(0);
  first.on_done = [&]() { ares_cancel(channel_); };
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &first));
  EXPECT_EQ(ARES_SUCCESS, Start("first.example", &follower));
  EXPECT_EQ(ARES_SUCCESS, Start("pending.example", &pending));
  Process(2000);
  EXPECT_EQ(ARES_SUCCESS, ares_queue_wait_empty(channel_, 100));
  ExpectQueueResult(first, ARES_SUCCESS);
  ExpectQueueResult(follower, ARES_ECANCELLED);
  ExpectQueueResult(pending, ARES_ECANCELLED);
}

static std::string QueryQueueEventParamName(
  const testing::TestParamInfo<std::tuple<ares_evsys_t, int, bool>> &info)
{
  return "Event" + std::to_string(static_cast<int>(std::get<0>(info.param))) +
         "_" + af_tostr(std::get<1>(info.param)) + "_" +
         mode_tostr(std::get<2>(info.param));
}

INSTANTIATE_TEST_SUITE_P(AddressFamilies, QueryQueueEventTest,
                         ::testing::ValuesIn(ares::test::evsys_families_modes),
                         QueryQueueEventParamName);
#endif

INSTANTIATE_TEST_SUITE_P(AddressFamilies, QueryQueueMultiTest,
                         ::testing::ValuesIn(ares::test::families_modes),
                         PrintFamilyMode);
INSTANTIATE_TEST_SUITE_P(AddressFamilies, QueryQueueTest,
                         ::testing::ValuesIn(ares::test::families_modes),
                         PrintFamilyMode);
INSTANTIATE_TEST_SUITE_P(AddressFamilies, QueryQueueCacheTest,
                         ::testing::ValuesIn(ares::test::families_modes),
                         PrintFamilyMode);

} /* namespace test */
} /* namespace ares */
