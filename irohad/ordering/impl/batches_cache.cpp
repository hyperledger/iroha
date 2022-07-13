/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/batches_cache.hpp"

#include <fmt/core.h>
#include <mutex>

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"
#include "main/subscription.hpp"

namespace {
  shared_model::interface::types::TimestampType oldestTimestamp(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
    if (!batch->transactions().empty()) {
      auto it = batch->transactions().begin();
      shared_model::interface::types::TimestampType ts = (*it)->createdTime();
      while (++it != batch->transactions().end())
        ts = std::min(ts, (*it)->createdTime());
      return ts;
    }
    return 0ull;
  }

  bool mergeSignaturesInBatch(
      std::shared_ptr<shared_model::interface::TransactionBatch> &target,
      std::shared_ptr<shared_model::interface::TransactionBatch> const &donor) {
    assert(target->transactions().size() == donor->transactions().size());
    auto inserted_new_signatures = false;

    auto it_target = target->transactions().begin();
    auto it_donor = donor->transactions().begin();
    while (it_target != target->transactions().end()
           && it_donor != donor->transactions().end()) {
      const auto &target_tx = *it_target++;
      const auto &donor_tx = *it_donor++;

      for (auto &signature : donor_tx->signatures())
        inserted_new_signatures |= target_tx->addSignature(
            shared_model::interface::types::SignedHexStringView{
                signature.signedData()},
            shared_model::interface::types::PublicKeyHexStringView{
                signature.publicKey()});
    }
    return inserted_new_signatures;
  }

  bool isExpired(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch,
      std::chrono::minutes const &expiration_range,
      const iroha::ordering::BatchesCache::TimeType &current_time) {
    return oldestTimestamp(batch)
        + expiration_range / std::chrono::milliseconds(1)
        < current_time;
  }
}  // namespace

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

  BatchesCache::BatchesCache(std::chrono::minutes const &expiration_range)
      : mst_state_(
            std::make_shared<utils::ReadWriteObject<MSTState, std::mutex>>()) {
    getSubscription()->dispatcher()->repeat(
        SubscriptionEngineHandlers::kNotifications,
        std::chrono::seconds(10ull),  /// repeat task execution period
        [expiration_range, w_mst_state(utils::make_weak(mst_state_))]() {
          if (auto s_mst_state = w_mst_state.lock()) {
            auto const now = std::chrono::system_clock::now().time_since_epoch()
                / std::chrono::milliseconds(1);

            s_mst_state->exclusiveAccess(
                [now, expiration_range](auto &mst_state) {
                  auto it = mst_state.mst_expirations_.begin();
                  while (it != mst_state.mst_expirations_.end()
                         && isExpired(it->second, expiration_range, now)) {
                    auto batch = it->second;
                    it = (mst_state -= it);
                    notifyEngine(std::make_tuple(std::make_pair(
                        EventTypes::kOnMstExpiredBatches, batch)));
                  }
                  notifyEngine(std::make_tuple(
                      std::make_pair(EventTypes::kOnMstMetrics,
                                     mst_state.batches_and_txs_counter)));
                  assert(mst_state.mst_pending_.size()
                         == mst_state.mst_expirations_.size());
                });
          }
        },
        [w_mst_state(utils::make_weak(mst_state_))]() {
          return !w_mst_state.expired();
        });
  }

  void BatchesCache::insertMSTCache(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
    assert(!batch->hasAllSignatures());
    mst_state_->exclusiveAccess([&](auto &mst_state) {
      auto ins_res =
          mst_state.mst_pending_.emplace(batch->reducedHash(), batch);
      auto &it_batch = ins_res.first;
      if (ins_res.second) {
        auto ts = oldestTimestamp(batch);
        while (!mst_state.mst_expirations_.emplace(ts, batch).second) ++ts;
        it_batch->second.timestamp = ts;
        mst_state += batch;
        notifyEngine(std::make_tuple(
            std::make_pair(EventTypes::kOnMstStateUpdate, batch),
            std::make_pair(EventTypes::kOnMstMetrics,
                           mst_state.batches_and_txs_counter)));
      } else {
        if (mergeSignaturesInBatch(it_batch->second.batch, batch)) {
          if (it_batch->second.batch->hasAllSignatures()) {
            batches_cache_.insert(it_batch->second.batch);
            mst_state -= it_batch;
            notifyEngine(std::make_tuple(
                std::make_pair(EventTypes::kOnMstPreparedBatches,
                               it_batch->second.batch),
                std::make_pair(EventTypes::kOnMstMetrics,
                               mst_state.batches_and_txs_counter)));
          } else {
            notifyEngine(std::make_tuple(std::make_pair(
                EventTypes::kOnMstStateUpdate, it_batch->second.batch)));
          }
        }
      }
      assert(mst_state.mst_pending_.size()
             == mst_state.mst_expirations_.size());
    });
  }

  void BatchesCache::removeMSTCache(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
    mst_state_->exclusiveAccess([&](auto &mst_state) {
      if (auto it = mst_state.mst_pending_.find(batch->reducedHash());
          it != mst_state.mst_pending_.end()) {
        mst_state -= it;
        notifyEngine(std::make_tuple(std::make_pair(
            EventTypes::kOnMstMetrics, mst_state.batches_and_txs_counter)));
        assert(mst_state.mst_pending_.size()
               == mst_state.mst_expirations_.size());
      }
    });
  }

  void BatchesCache::removeMSTCache(
      OnDemandOrderingService::HashesSetType const &hashes) {
    mst_state_->exclusiveAccess([&](auto &mst_state) {
      for (auto it = mst_state.mst_pending_.begin();
           it != mst_state.mst_pending_.end();) {
        auto const &batch_info = it->second;
        auto const need_remove =
            std::any_of(batch_info.batch->transactions().begin(),
                        batch_info.batch->transactions().end(),
                        [&hashes](auto const &tx) {
                          return hashes.find(tx->hash()) != hashes.end();
                        });
        if (need_remove) {
          it = (mst_state -= it);
        } else
          ++it;
      }
      notifyEngine(std::make_tuple(std::make_pair(
          EventTypes::kOnMstMetrics, mst_state.batches_and_txs_counter)));
      assert(mst_state.mst_pending_.size()
             == mst_state.mst_expirations_.size());
    });
  }

  uint64_t BatchesCache::insert(
      std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
    std::unique_lock lock(batches_cache_cs_);

    if (batch->hasAllSignatures()) {
      if (used_batches_cache_.getBatchesSet().find(batch)
          == used_batches_cache_.getBatchesSet().end())
        batches_cache_.insert(batch);
      removeMSTCache(batch);
      notifyEngine(std::make_tuple(
          std::make_pair(EventTypes::kOnMstPreparedBatches, batch)));
    } else
      insertMSTCache(batch);

    return batches_cache_.getTxsCount();
  }

  void BatchesCache::remove(
      const OnDemandOrderingService::HashesSetType &hashes) {
    removeMSTCache(hashes);

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
    /// TODO(iceseer): batches push by reference
    std::unique_lock lock(batches_cache_cs_);
    for (auto &batch : batches) {
      batches_cache_.removeBatch(batch);
      used_batches_cache_.insert(batch);
    }
  }

}  // namespace iroha::ordering
