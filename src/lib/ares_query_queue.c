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
#include <assert.h>

#define ARES_QUERY_GROUP_LIMIT 32768

typedef struct {
  ares_query_group_t  *group;
  ares_callback_dnsrec callback;
  void                *arg;
  size_t               handle;
  size_t               joined_timeouts;
  ares_bool_t          no_retries;
  ares_llist_node_t   *global_node;
  ares_llist_node_t   *group_node;
  ares_status_t        ready_status;
  size_t               ready_timeouts;
  ares_dns_record_t   *ready_response;
} ares_query_waiter_t;

struct ares_query_group {
  ares_channel_t    *channel;
  size_t             refs;
  unsigned short     qid;
  ares_send_flags_t  flags;
  ares_dns_record_t *request;
  char              *qcache_key;
  unsigned char     *key;
  size_t             key_len;
  ares_bool_t        indexed;
  ares_bool_t        reserved;
  ares_query_t      *wire;
  ares_llist_t      *waiters;
  ares_llist_node_t *all_node;
  ares_llist_node_t *pending_node;
};

struct ares_query_queue {
  size_t               max_active;
  size_t               max_pending;
  ares_bool_t          coalesce;
  size_t               busy;
  size_t               next_handle;
  size_t               ungrouped_queries;
  ares_llist_t        *groups;
  ares_llist_t        *pending;
  ares_llist_t        *waiters;
  ares_llist_t        *ready;
  ares_llist_t        *cancelling;
  ares_htable_szvp_t  *reserved;
  ares_htable_szvp_t  *handles;
  ares_htable_binvp_t *identical;
};

static void group_release(ares_query_group_t *group)
{
  group->refs--;
  if (group->refs != 0) {
    return;
  }
  ares_dns_record_destroy(group->request);
  ares_free(group->qcache_key);
  ares_free(group->key);
  ares_llist_destroy(group->waiters);
  ares_free(group);
}

static void group_retire(ares_query_group_t *group)
{
  ares_query_queue_t *queue = group->channel->query_queue;
  if (group->indexed) {
    ares_htable_binvp_remove(queue->identical, group->key, group->key_len);
    group->indexed = ARES_FALSE;
  }
  if (group->reserved) {
    ares_htable_szvp_remove(queue->reserved, group->qid);
    group->reserved = ARES_FALSE;
  }
  ares_llist_node_destroy(group->pending_node);
  group->pending_node = NULL;
  ares_llist_node_destroy(group->all_node);
  group->all_node = NULL;
}

static void waiter_finish(ares_query_waiter_t *waiter, ares_status_t status,
                          size_t timeouts, const ares_dns_record_t *response)
{
  ares_query_group_t  *group          = waiter->group;
  ares_query_queue_t  *queue          = group->channel->query_queue;
  ares_callback_dnsrec callback       = waiter->callback;
  void                *arg            = waiter->arg;
  ares_dns_record_t   *owned_response = waiter->ready_response;

  /* Claim before invoking user code. Other, unclaimed waiters stay cancellable,
   * including followers of a response currently being dispatched. */
  ares_htable_szvp_remove(queue->handles, waiter->handle);
  ares_llist_node_destroy(waiter->global_node);
  ares_llist_node_destroy(waiter->group_node);
  ares_free(waiter);
  group_release(group);
  callback(arg, status, timeouts, response);
  ares_dns_record_destroy(owned_response);
}

static void group_complete(void *arg, ares_status_t status, size_t timeouts,
                           const ares_dns_record_t *response)
{
  ares_query_group_t  *group   = arg;
  ares_channel_t      *channel = group->channel;
  ares_query_queue_t  *queue   = channel->query_queue;
  ares_query_waiter_t *waiter;

  queue->busy++;
  group->wire = NULL;
  group_retire(group);
  while ((waiter = ares_llist_first_val(group->waiters)) != NULL) {
    size_t observed = timeouts >= waiter->joined_timeouts
                        ? timeouts - waiter->joined_timeouts
                        : 0;
    waiter_finish(waiter, status, observed, response);
  }
  /* Keep the dispatch owner's reference through all reentrant callbacks. */
  group_release(group);
  queue->busy--;
  ares_query_queue_pump(channel);
  ares_queue_notify_empty(channel);
}

void ares_query_queue_set_query(ares_query_group_t *group, ares_query_t *query)
{
  if (group != NULL) {
    group->wire = query;
  }
}

void ares_query_queue_track_direct(ares_query_t *query)
{
  ares_query_queue_t *queue = query->channel->query_queue;
  if (queue != NULL && query->queue_group == NULL) {
    queue->ungrouped_queries++;
  }
}

void ares_query_queue_detach_query(ares_query_t *query)
{
  ares_query_queue_t *queue = query->channel->query_queue;
  if (queue == NULL || query->queue_group != NULL ||
      ares_htable_szvp_get_direct(query->channel->queries_by_qid, query->qid) !=
        query) {
    return;
  }
  assert(queue->ungrouped_queries != 0);
  queue->ungrouped_queries--;
}

ares_bool_t ares_query_queue_has_slot(const ares_channel_t *channel)
{
  const ares_query_queue_t *queue = channel->query_queue;
  size_t                    active;
  if (queue == NULL || queue->max_active == 0) {
    return ARES_TRUE;
  }
  active = ares_htable_szvp_num_keys(channel->queries_by_qid);
  assert(active >= queue->ungrouped_queries);
  active -= queue->ungrouped_queries;
  return active < queue->max_active ? ARES_TRUE : ARES_FALSE;
}

static ares_bool_t id_used(const ares_channel_t *channel, unsigned short id)
{
  return (ares_htable_szvp_get(channel->queries_by_qid, id, NULL) ||
          (channel->query_queue != NULL &&
           ares_htable_szvp_get(channel->query_queue->reserved, id, NULL)))
           ? ARES_TRUE
           : ARES_FALSE;
}

ares_status_t ares_query_queue_new_id(ares_channel_t *channel,
                                      unsigned short *id)
{
  size_t i;
  /* The enabled scheduler reserves at most half the namespace. Bound random
   * retries anyway, including legacy channels that have no admission limit. */
  for (i = 0; i < 64; i++) {
    *id = ares_generate_new_id(channel->rand_state);
    if (!id_used(channel, *id)) {
      return ARES_SUCCESS;
    }
  }
  for (i = 0; i < 65536; i++) {
    *id = (unsigned short)(*id + 1);
    if (!id_used(channel, *id)) {
      return ARES_SUCCESS;
    }
  }
  return ARES_EQUEUEFULL;
}

void ares_query_queue_pump(ares_channel_t *channel)
{
  ares_query_queue_t *queue = channel->query_queue;
  if (queue == NULL || queue->busy != 0 || channel->query_queue_holds != 0 ||
      !channel->sys_up) {
    return;
  }
  queue->busy++;
  for (;;) {
    ares_query_waiter_t *waiter = ares_llist_first_val(queue->ready);
    ares_query_group_t  *group;
    char                *qcache_key;
    if (waiter != NULL) {
      waiter_finish(waiter, waiter->ready_status, waiter->ready_timeouts,
                    waiter->ready_response);
      continue;
    }
    if (!ares_query_queue_has_slot(channel)) {
      break;
    }
    group = ares_llist_first_val(queue->pending);
    if (group == NULL) {
      break;
    }
    ares_llist_node_destroy(group->pending_node);
    group->pending_node = NULL;
    /* group_complete owns the group's initial reference. It may run before
     * this returns, so neither group nor caller output pointers are used after
     * dispatch. Retries use the same active transaction. */
    qcache_key        = group->qcache_key;
    group->qcache_key = NULL;
    ares_send_direct_nolock(channel, NULL, group->flags, group->request,
                            qcache_key, group_complete, group, group->qid,
                            group);
  }
  queue->busy--;
  ares_queue_notify_empty(channel);
}

static ares_status_t make_key(ares_query_group_t *group)
{
  ares_buf_t    *buf      = NULL;
  unsigned char *wire     = NULL;
  size_t         wire_len = 0;
  ares_status_t  status;

  /* Normalize only the library-owned transaction ID. Preserve all flags,
   * question/RR bytes and ordering, EDNS contents and name case. */
  ares_dns_record_set_id(group->request, 0);
  status = ares_dns_write(group->request, &wire, &wire_len);
  if (status != ARES_SUCCESS) {
    goto done;
  }
  buf = ares_buf_create();
  if (buf == NULL) {
    status = ARES_ENOMEM;
    goto done;
  }
  status = ares_buf_append_be32(buf, (unsigned int)group->flags);
  if (status == ARES_SUCCESS) {
    status = ares_buf_append(buf, wire, wire_len);
  }
  if (status == ARES_SUCCESS) {
    group->key = ares_buf_finish_bin(buf, &group->key_len);
    buf        = NULL;
    if (group->key == NULL) {
      status = ARES_ENOMEM;
    }
  }
done:
  ares_buf_destroy(buf);
  ares_free(wire);
  return status;
}

static ares_status_t add_waiter(ares_query_group_t  *group,
                                ares_callback_dnsrec callback, void *arg,
                                size_t *handle)
{
  ares_query_queue_t  *queue  = group->channel->query_queue;
  ares_query_waiter_t *waiter = ares_malloc_zero(sizeof(*waiter));
  if (waiter == NULL) {
    return ARES_ENOMEM;
  }
  do {
    queue->next_handle++;
  } while (queue->next_handle == 0 ||
           ares_htable_szvp_get(queue->handles, queue->next_handle, NULL));
  waiter->handle   = queue->next_handle;
  waiter->group    = group;
  waiter->callback = callback;
  waiter->arg      = arg;
  waiter->no_retries =
    (group->flags & ARES_SEND_FLAG_NORETRY) ? ARES_TRUE : ARES_FALSE;
  waiter->joined_timeouts = group->wire == NULL ? 0 : group->wire->timeouts;
  waiter->global_node     = ares_llist_insert_last(queue->waiters, waiter);
  waiter->group_node      = ares_llist_insert_last(group->waiters, waiter);
  if (waiter->global_node == NULL || waiter->group_node == NULL ||
      !ares_htable_szvp_insert(queue->handles, waiter->handle, waiter)) {
    ares_llist_node_destroy(waiter->global_node);
    ares_llist_node_destroy(waiter->group_node);
    ares_free(waiter);
    return ARES_ENOMEM;
  }
  group->refs++;
  *handle = waiter->handle;
  return ARES_SUCCESS;
}

ares_status_t ares_query_queue_admit(ares_channel_t          *channel,
                                     ares_send_flags_t        flags,
                                     const ares_dns_record_t *dnsrec,
                                     char                    *qcache_key,
                                     ares_callback_dnsrec callback, void *arg,
                                     unsigned short *qid, size_t *handle)
{
  ares_query_queue_t *queue = channel->query_queue;
  ares_query_group_t *group = NULL;
  ares_query_group_t *existing;
  ares_status_t       status         = ARES_ENOMEM;
  size_t              logical_handle = 0;
  size_t              capacity = queue->max_active == 0
                                   ? ARES_QUERY_GROUP_LIMIT
                                   : queue->max_active + queue->max_pending;

  group = ares_malloc_zero(sizeof(*group));
  if (group == NULL) {
    goto fail;
  }
  group->channel    = channel;
  group->refs       = 1;
  group->flags      = flags;
  group->qcache_key = qcache_key;
  qcache_key        = NULL;
  status            = ares_dns_record_duplicate_ex(&group->request, dnsrec);
  if (status != ARES_SUCCESS) {
    if (status == ARES_EBADRESP) {
      status = ARES_EBADQUERY;
    }
    goto fail;
  }
  if (queue->coalesce) {
    status = make_key(group);
    if (status != ARES_SUCCESS) {
      goto fail;
    }
    existing = ares_htable_binvp_get_direct(queue->identical, group->key,
                                            group->key_len);
    if (existing != NULL) {
      group_release(group);
      group  = NULL;
      status = add_waiter(existing, callback, arg, &logical_handle);
      if (status != ARES_SUCCESS) {
        goto fail;
      }
      if (qid != NULL) {
        *qid = existing->qid;
      }
      if (handle != NULL) {
        *handle = logical_handle;
      }
      return ARES_SUCCESS;
    }
  }
  if (ares_llist_len(queue->groups) >= capacity) {
    status = ARES_EQUEUEFULL;
    goto fail;
  }
  status = ares_query_queue_new_id(channel, &group->qid);
  if (status != ARES_SUCCESS) {
    goto fail;
  }
  status         = ARES_ENOMEM;
  group->waiters = ares_llist_create(NULL);
  if (group->waiters == NULL) {
    goto fail;
  }
  group->all_node     = ares_llist_insert_last(queue->groups, group);
  group->pending_node = ares_llist_insert_last(queue->pending, group);
  if (group->all_node == NULL || group->pending_node == NULL ||
      !ares_htable_szvp_insert(queue->reserved, group->qid, group)) {
    goto fail;
  }
  group->reserved = ARES_TRUE;
  if (queue->coalesce) {
    if (!ares_htable_binvp_insert(queue->identical, group->key, group->key_len,
                                  group)) {
      goto fail;
    }
    group->indexed = ARES_TRUE;
  }
  status = add_waiter(group, callback, arg, &logical_handle);
  if (status != ARES_SUCCESS) {
    goto fail;
  }
  if (qid != NULL) {
    *qid = group->qid;
  }
  if (handle != NULL) {
    *handle = logical_handle;
  }
  ares_query_queue_pump(channel);
  return ARES_SUCCESS;

fail:
  if (group != NULL) {
    group_retire(group);
    group_release(group);
  }
  ares_free(qcache_key);
  callback(arg, status, 0, NULL);
  return status;
}

void ares_query_queue_stop_retry(const ares_channel_t *channel, size_t handle)
{
  ares_query_waiter_t *waiter;
  if (channel->query_queue == NULL || handle == 0) {
    return;
  }
  waiter = ares_htable_szvp_get_direct(channel->query_queue->handles, handle);
  if (waiter != NULL) {
    waiter->no_retries = ARES_TRUE;
  }
}

void ares_query_queue_retry(ares_query_t            *query,
                            const ares_dns_record_t *response)
{
  ares_query_group_t *group = query->queue_group;
  ares_query_queue_t *queue;
  ares_llist_node_t  *node;
  size_t              retrying = 0;

  if (group == NULL) {
    return;
  }
  queue = group->channel->query_queue;
  for (node = ares_llist_node_first(group->waiters); node != NULL;
       node = ares_llist_node_next(node)) {
    ares_query_waiter_t *waiter = ares_llist_node_val(node);
    if (!waiter->no_retries) {
      retrying++;
    }
  }
  if (retrying == 0) {
    query->no_retries = ARES_TRUE;
    return;
  }
  node = ares_llist_node_first(group->waiters);
  while (node != NULL) {
    ares_llist_node_t   *next   = ares_llist_node_next(node);
    ares_query_waiter_t *waiter = ares_llist_node_val(node);
    if (waiter->no_retries) {
      waiter->ready_status   = query->error_status == ARES_SUCCESS
                                 ? ARES_ETIMEOUT
                                 : query->error_status;
      waiter->ready_timeouts = query->timeouts - waiter->joined_timeouts;
      if (response != NULL) {
        ares_status_t status =
          ares_dns_record_duplicate_ex(&waiter->ready_response, response);
        if (status != ARES_SUCCESS) {
          waiter->ready_status = status;
        }
      }
      ares_llist_node_mvparent_last(node, queue->ready);
    }
    node = next;
  }
}

void ares_query_queue_cancel(ares_channel_t *channel, ares_status_t status)
{
  ares_query_queue_t  *queue = channel->query_queue;
  ares_llist_node_t   *node;
  ares_query_group_t  *group;
  ares_query_waiter_t *waiter;

  /* Move the current callers to the preallocated cancellation list. New work
   * created by callbacks remains on waiters and survives this cancellation
   * unless a reentrant cancel moves it to the tail of the same list. Store the
   * status per caller so a nested ares_cancel() during destruction cannot
   * change ARES_EDESTRUCTION for callers already being drained. */
  while ((node = ares_llist_node_first(queue->waiters)) != NULL) {
    waiter               = ares_llist_node_val(node);
    waiter->ready_status = status;
    ares_llist_node_mvparent_last(node, queue->cancelling);
  }
  queue->busy++;
  /* Retire every old group before invoking any cancellation callback. New
   * identical requests therefore cannot attach to work being cancelled. */
  while ((group = ares_llist_first_val(queue->groups)) != NULL) {
    if (group->wire != NULL) {
      ares_free_query(group->wire);
      group->wire = NULL;
    }
    group_retire(group);
    group_release(group);
  }
  /* Remaining transport queries are explicit-server recovery probes. They
   * have no public logical waiter and their callback only releases probe state.
   */
  while (ares_llist_len(channel->all_queries) != 0) {
    ares_query_t *query = ares_llist_first_val(channel->all_queries);
    ares_detach_query(query);
    query->callback(query->arg, status, 0, NULL);
    ares_free_query(query);
  }
  while ((waiter = ares_llist_first_val(queue->cancelling)) != NULL) {
    waiter_finish(waiter, waiter->ready_status, 0, NULL);
  }
  queue->busy--;
  ares_query_queue_pump(channel);
}

void ares_query_queue_invalidate(ares_channel_t *channel)
{
  ares_query_queue_t *queue = channel->query_queue;
  ares_llist_node_t  *node;
  if (queue == NULL) {
    return;
  }
  for (node = ares_llist_node_first(queue->groups); node != NULL;
       node = ares_llist_node_next(node)) {
    ares_query_group_t *group = ares_llist_node_val(node);
    if (group->indexed) {
      ares_htable_binvp_remove(queue->identical, group->key, group->key_len);
      group->indexed = ARES_FALSE;
    }
  }
}

void ares_query_queue_config_start(ares_channel_t *channel)
{
  channel->query_queue_holds++;
  if (channel->query_queue != NULL) {
    ares_query_queue_invalidate(channel);
  }
}

void ares_query_queue_config_end(ares_channel_t *channel)
{
  channel->query_queue_holds--;
  if (channel->query_queue != NULL) {
    ares_query_queue_invalidate(channel);
    ares_query_queue_pump(channel);
  }
}

ares_bool_t ares_query_queue_probe_allowed(const ares_channel_t *channel)
{
  if (!channel->sys_up || channel->query_queue_holds != 0) {
    return ARES_FALSE;
  }
  return ARES_TRUE;
}

size_t ares_query_queue_count(const ares_channel_t *channel)
{
  if (channel->query_queue == NULL) {
    return ares_llist_len(channel->all_queries);
  }
  return ares_htable_szvp_num_keys(channel->query_queue->handles) +
         channel->query_queue->ungrouped_queries;
}

void ares_query_queue_destroy(ares_channel_t *channel)
{
  ares_query_queue_t *queue = channel->query_queue;
  if (queue == NULL) {
    return;
  }
  ares_llist_destroy(queue->groups);
  ares_llist_destroy(queue->pending);
  ares_llist_destroy(queue->waiters);
  ares_llist_destroy(queue->ready);
  ares_llist_destroy(queue->cancelling);
  ares_htable_szvp_destroy(queue->reserved);
  ares_htable_szvp_destroy(queue->handles);
  ares_htable_binvp_destroy(queue->identical);
  ares_free(queue);
  channel->query_queue = NULL;
}

ares_status_t ares_set_query_queue_options(ares_channel_t *channel,
                                           size_t          max_active,
                                           size_t          max_pending,
                                           ares_bool_t     coalesce)
{
  ares_query_queue_t *queue;
  ares_status_t       status = ARES_SUCCESS;
  if (channel == NULL || max_active > ARES_QUERY_GROUP_LIMIT ||
      max_pending > ARES_QUERY_GROUP_LIMIT - max_active ||
      (max_active == 0 && max_pending != 0) ||
      (coalesce != ARES_TRUE && coalesce != ARES_FALSE)) {
    return ARES_EFORMERR;
  }
  ares_channel_lock(channel);
  if (channel->query_queue_holds != 0 || ares_query_queue_count(channel) != 0 ||
      (channel->query_queue != NULL && channel->query_queue->busy != 0)) {
    status = ARES_EBUSY;
    goto done;
  }
  if (max_active == 0 && !coalesce) {
    ares_query_queue_destroy(channel);
    goto done;
  }
  queue = channel->query_queue;
  if (queue == NULL) {
    queue = ares_malloc_zero(sizeof(*queue));
    if (queue == NULL) {
      status = ARES_ENOMEM;
      goto done;
    }
    channel->query_queue = queue;
    queue->groups        = ares_llist_create(NULL);
    queue->pending       = ares_llist_create(NULL);
    queue->waiters       = ares_llist_create(NULL);
    queue->ready         = ares_llist_create(NULL);
    queue->cancelling    = ares_llist_create(NULL);
    queue->reserved      = ares_htable_szvp_create(NULL);
    queue->handles       = ares_htable_szvp_create(NULL);
    queue->identical     = ares_htable_binvp_create(NULL);
    if (queue->groups == NULL || queue->pending == NULL ||
        queue->waiters == NULL || queue->ready == NULL ||
        queue->cancelling == NULL || queue->reserved == NULL ||
        queue->handles == NULL || queue->identical == NULL) {
      ares_query_queue_destroy(channel);
      status = ARES_ENOMEM;
      goto done;
    }
  }
  queue->max_active  = max_active;
  queue->max_pending = max_pending;
  queue->coalesce    = coalesce;
done:
  ares_channel_unlock(channel);
  return status;
}

ares_status_t ares_get_query_queue_options(const ares_channel_t *channel,
                                           size_t               *max_active,
                                           size_t               *max_pending,
                                           ares_bool_t          *coalesce)
{
  if (channel == NULL || max_active == NULL || max_pending == NULL ||
      coalesce == NULL) {
    return ARES_EFORMERR;
  }
  ares_channel_lock(channel);
  *max_active =
    channel->query_queue == NULL ? 0 : channel->query_queue->max_active;
  *max_pending =
    channel->query_queue == NULL ? 0 : channel->query_queue->max_pending;
  *coalesce =
    channel->query_queue == NULL ? ARES_FALSE : channel->query_queue->coalesce;
  ares_channel_unlock(channel);
  return ARES_SUCCESS;
}

ares_status_t ares_query_queue_dup(ares_channel_t       *dest,
                                   const ares_channel_t *src)
{
  size_t        max_active;
  size_t        max_pending;
  ares_bool_t   coalesce;
  ares_status_t status =
    ares_get_query_queue_options(src, &max_active, &max_pending, &coalesce);
  if (status != ARES_SUCCESS) {
    return status;
  }
  return ares_set_query_queue_options(dest, max_active, max_pending, coalesce);
}
