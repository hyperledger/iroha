/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/ordering_gate_cache/on_demand_cache.hpp"

#include <numeric>

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"

using namespace iroha::ordering::cache;

// TODO: IR-1864 13.11.18 kamilsa use nvi to separate business logic and locking
// logic

namespace {
  uint64_t countTransactions(const OrderingGateCache::BatchesSetType &batches) {
    return std::accumulate(batches.begin(),
                           batches.end(),
                           0u,
                           [](const uint64_t txs_quantity, const auto &batch) {
                             return txs_quantity
                                 + boost::size(batch->transactions());
                           });
  }
}  // namespace

OnDemandCache::OnDemandCache(uint64_t max_cache_size)
    : max_cache_size_(max_cache_size) {}

bool OnDemandCache::addToBack(
    const OrderingGateCache::BatchesSetType &batches) {
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
  const uint64_t input_size = countTransactions(batches);

  if (circ_buffer.back().first + input_size > max_cache_size_) {
    return false;
  }
  circ_buffer.back().first += input_size;
  circ_buffer.back().second.insert(batches.begin(), batches.end());
  return true;
}

void OnDemandCache::remove(const OrderingGateCache::HashesSetType &hashes) {
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
  for (auto &batches : circ_buffer) {
    for (auto it = batches.second.begin(); it != batches.second.end();) {
      if (std::any_of(it->get()->transactions().begin(),
                      it->get()->transactions().end(),
                      [&hashes](const auto &tx) {
                        return hashes.find(tx->hash()) != hashes.end();
                      })) {
        // returns iterator following the last removed element
        // hence there is no increment in loop iteration_expression
        batches.first -= boost::size((*it)->transactions());
        it = batches.second.erase(it);
      } else {
        ++it;
      }
    }
  }
}

OrderingGateCache::BatchesSetType OnDemandCache::pop() {
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
  BatchesSetType res;
  std::swap(res, circ_buffer.front().second);
  // push empty set to remove front element
  circ_buffer.push_back(std::make_pair(0, BatchesSetType{}));
  return res;
}

const OrderingGateCache::BatchesSetType &OnDemandCache::front() const {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  return circ_buffer.front().second;
}

const OrderingGateCache::BatchesSetType &OnDemandCache::back() const {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  return circ_buffer.back().second;
}

void OnDemandCache::rotate() {
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
  auto second_element_it = boost::next(circ_buffer.begin());
  circ_buffer.rotate(second_element_it);
}

size_t OnDemandCache::availableTxsCapacity() const {
  return max_cache_size_ - circ_buffer.back().first;
}
