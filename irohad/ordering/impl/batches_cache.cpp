/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/batches_cache.hpp"

#include <fmt/core.h>
#include <iostream>
#include <mutex>

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"

namespace iroha::ordering {

  BatchesContext::BatchesContext() : tx_count_(0ull) {}

  uint64_t BatchesContext::count(BatchesSetType const &src) {
    return std::accumulate(src.begin(),
                           src.end(),
                           0ull,
                           [](unsigned long long sum, auto const &batch) {
                             return sum + batch->transactions().size();
                           });
  }

  uint64_t BatchesContext::getTxsCount() const {
    return tx_count_;
  }

  BatchesContext::BatchesSetType &BatchesContext::getBatchesSet() {
    return batches_;
  }

  bool BatchesContext::insert(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
    auto const inserted = batches_.insert(batch).second;
    if (inserted)
      tx_count_ += batch->transactions().size();

    assert(count(batches_) == tx_count_);
    return inserted;
  }

  bool BatchesContext::removeBatch(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
    auto const was = batches_.size();
    batches_.erase(batch);
    if (batches_.size() != was)
      tx_count_ -= batch->transactions().size();

    assert(count(batches_) == tx_count_);
    return (was != batches_.size());
  }

  void BatchesContext::merge(BatchesContext &from) {
    auto it = from.batches_.begin();
    while (it != from.batches_.end())
      if (batches_.insert(*it).second) {
        auto const tx_count = (*it)->transactions().size();
        it = from.batches_.erase(it);

        tx_count_ += tx_count;
        from.tx_count_ -= tx_count;
      } else
        ++it;

    assert(count(batches_) == tx_count_);
    assert(count(from.batches_) == from.tx_count_);
  }

  uint64_t BatchesCache::insert(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
    std::unique_lock lock(batches_cache_cs_);

    if (used_batches_cache_.getBatchesSet().find(batch)
        == used_batches_cache_.getBatchesSet().end())
      batches_cache_.insert(batch);

    return batches_cache_.getTxsCount();
  }

  void BatchesCache::remove(
      const OnDemandOrderingService::HashesSetType &hashes) {
    std::unique_lock lock(batches_cache_cs_);

    batches_cache_.merge(used_batches_cache_);
    assert(used_batches_cache_.getTxsCount() == 0ull);

    batches_cache_.remove([&](auto &batch, bool & /*process_iteration*/) {
      return std::any_of(batch->transactions().begin(),
                         batch->transactions().end(),
                         [&hashes](const auto &tx) {
                           return hashes.find(tx->hash()) != hashes.end();
                         });
    });
  }

  bool BatchesCache::isEmpty() {
    std::shared_lock lock(batches_cache_cs_);
    return batches_cache_.getBatchesSet().empty();
  }

  uint64_t BatchesCache::txsCount() const {
    std::shared_lock lock(batches_cache_cs_);
    return batches_cache_.getTxsCount() + used_batches_cache_.getTxsCount();
  }

  uint64_t BatchesCache::availableTxsCount() const {
    std::shared_lock lock(batches_cache_cs_);
    return batches_cache_.getTxsCount();
  }

  void BatchesCache::forCachedBatches(
      std::function<void(BatchesSetType &)> const &f) {
    std::unique_lock lock(batches_cache_cs_);
    f(batches_cache_.getBatchesSet());
  }

  void BatchesCache::processReceivedProposal(
      OnDemandOrderingService::CollectionType batches) {
    std::unique_lock lock(batches_cache_cs_);
    for (auto &batch : batches) {
      batches_cache_.removeBatch(batch);
      used_batches_cache_.insert(batch);
    }
  }

}  // namespace iroha::ordering
