/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/ordering_gate_cache/on_demand_cache.hpp"

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"

using namespace iroha::ordering::cache;

// TODO: IR-1864 13.11.18 kamilsa use nvi to separate business logic and locking
// logic

void OnDemandCache::addToBack(
    const OrderingGateCache::BatchesSetType &batches) {
  std::unique_lock<std::shared_timed_mutex> lock(mutex_);
  circ_buffer.back().insert(batches.begin(), batches.end());
}

void OnDemandCache::remove(const OrderingGateCache::HashesSetType &hashes) {
  std::unique_lock<std::shared_timed_mutex> lock(mutex_);
  for (auto &batches : circ_buffer) {
    for (auto it = batches.begin(); it != batches.end();) {
      if (std::any_of(it->get()->transactions().begin(),
                      it->get()->transactions().end(),
                      [&hashes](const auto &tx) {
                        return hashes.find(tx->hash()) != hashes.end();
                      })) {
        // returns iterator following the last removed element
        // hence there is no increment in loop iteration_expression
        it = batches.erase(it);
      } else {
        ++it;
      }
    }
  }
}

OrderingGateCache::BatchesSetType OnDemandCache::pop() {
  std::unique_lock<std::shared_timed_mutex> lock(mutex_);
  BatchesSetType res;
  std::swap(res, circ_buffer.front());
  // push empty set to remove front element
  circ_buffer.push_back(BatchesSetType{});
  return res;
}

const OrderingGateCache::BatchesSetType &OnDemandCache::head() const {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  return circ_buffer.front();
}

const OrderingGateCache::BatchesSetType &OnDemandCache::tail() const {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  return circ_buffer.back();
}
