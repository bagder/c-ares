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
#ifndef ARES_QUERY_QUEUE_H
#define ARES_QUERY_QUEUE_H

/*! Admit a logical caller into the optional scheduler. The lock is held.
 * \param[in] channel Channel with scheduling enabled.
 * \param[in] flags Internal send policy.
 * \param[in] dnsrec Original query.
 * \param[in] qcache_key Owned completed-response cache key, or NULL.
 * \param[in] callback Completion callback.
 * \param[in] arg Callback argument.
 * \param[out] qid Optional actual reserved wire ID.
 * \param[out] handle Optional private logical caller ID.
 * \return Admission status; errors also invoke callback.
 */
ares_status_t ares_query_queue_admit(ares_channel_t          *channel,
                                     ares_send_flags_t        flags,
                                     const ares_dns_record_t *dnsrec,
                                     char                    *qcache_key,
                                     ares_callback_dnsrec callback, void *arg,
                                     unsigned short *qid, size_t *handle);

/*! Allocate an unused wire ID, excluding pending reservations.
 * \param[in] channel Locked channel.
 * \param[out] id Available ID, not yet reserved by this function.
 * \return ARES_SUCCESS or ARES_EQUEUEFULL.
 */
ares_status_t ares_query_queue_new_id(ares_channel_t *channel,
                                      unsigned short *id);

/*! Check user active capacity, excluding internal recovery probes.
 * \param[in] channel Locked channel.
 * \return Whether another transaction can start.
 */
ares_bool_t ares_query_queue_has_slot(const ares_channel_t *channel);

/*! Associate a just-created transport query with its owning group.
 * \param[in] group Optional group.
 * \param[in] query Transport query.
 */
void ares_query_queue_set_query(ares_query_group_t *group, ares_query_t *query);

/*! Count a direct transaction that is not owned by a scheduler group.
 * \param[in] query Newly indexed transport query.
 */
void ares_query_queue_track_direct(ares_query_t *query);

/*! Retire a direct transaction from the scheduler's constant-time count.
 * \param[in] query Transport query that is about to leave the qid table.
 */
void ares_query_queue_detach_query(ares_query_t *query);

/*! Drain deferred completions and promote waiting transactions iteratively.
 * \param[in] channel Locked channel, at a safe callback boundary.
 */
void ares_query_queue_pump(ares_channel_t *channel);

/*! Apply per-caller retry decisions without invoking callbacks.
 * \param[in] query Transaction at an attempt boundary.
 * \param[in] response Optional failed response, borrowed.
 */
void ares_query_queue_retry(ares_query_t            *query,
                            const ares_dns_record_t *response);

/*! Stop future retries for one logical caller only.
 * \param[in] channel Locked channel.
 * \param[in] handle Private logical caller ID, or zero for no caller.
 */
void ares_query_queue_stop_retry(const ares_channel_t *channel, size_t handle);

/*! Cancel a snapshot of callers and transactions, preserving callback-created
 * work. Does not promote work during destruction.
 * \param[in] channel Locked channel with scheduling enabled.
 * \param[in] status ARES_ECANCELLED or ARES_EDESTRUCTION.
 */
void ares_query_queue_cancel(ares_channel_t *channel, ares_status_t status);

/*! Destroy idle scheduler state.
 * \param[in] channel Channel whose scheduler is empty.
 */
void ares_query_queue_destroy(ares_channel_t *channel);

/*! Copy configuration only, never outstanding transactions.
 * \param[in] dest Empty destination channel.
 * \param[in] src Source channel.
 * \return Configuration status.
 */
ares_status_t ares_query_queue_dup(ares_channel_t       *dest,
                                   const ares_channel_t *src);

/*! Exclude existing groups from merging after routing configuration changes.
 * \param[in] channel Locked channel.
 */
void ares_query_queue_invalidate(ares_channel_t *channel);

/*! Defer promotion while a routing configuration is being changed.
 * \param[in] channel Locked channel.
 */
void ares_query_queue_config_start(ares_channel_t *channel);

/*! Finish a routing change, invalidate intermediate merge keys, then promote.
 * \param[in] channel Locked channel with a matching configuration start.
 */
void ares_query_queue_config_end(ares_channel_t *channel);

/*! Check whether a recovery probe can run outside a configuration update.
 * \param[in] channel Locked channel.
 * \return Whether a probe can start now.
 */
ares_bool_t ares_query_queue_probe_allowed(const ares_channel_t *channel);

/*! Count outstanding logical callers and ungrouped internal queries.
 * \param[in] channel Locked channel.
 * \return Outstanding count, including queued and completion-ready callers.
 */
size_t ares_query_queue_count(const ares_channel_t *channel);

#endif
