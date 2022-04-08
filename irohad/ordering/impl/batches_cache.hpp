/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BATCHES_CACHE_HPP
#define IROHA_BATCHES_CACHE_HPP

#include "ordering/on_demand_ordering_service.hpp"

#include <map>
#include <memory>
#include <numeric>
#include <set>
#include <shared_mutex>
#include <type_traits>
#include <unordered_map>

#include "common/common.hpp"
#include "consensus/round.hpp"
#include "ordering/ordering_types.hpp"

namespace shared_model::interface {
  class TransactionBatch;
}  // namespace shared_model::interface

namespace iroha::ordering {

  /**
   * Contains additional information about batches.
   */
  class BatchesContext {
   public:
    using BatchesSetType =
        std::set<std::shared_ptr<shared_model::interface::TransactionBatch>,
                 shared_model::interface::BatchHashLess>;

    BatchesContext(BatchesContext const &) = delete;
    BatchesContext &operator=(BatchesContext const &) = delete;
    BatchesContext();

   private:
    /// Save this value in additional field to avoid batches iteration on
    /// request.
    uint64_t tx_count_;
    BatchesSetType batches_;

    static uint64_t count(BatchesSetType const &src);

   public:
    uint64_t getTxsCount() const;

    BatchesSetType &getBatchesSet();

    bool insert(std::shared_ptr<shared_model::interface::TransactionBatch> const
                    &batch);

    bool removeBatch(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch);

    void merge(BatchesContext &from);

    template <typename _Predic>
    void remove(_Predic &&pred) {
      bool process_iteration = true;
      for (auto it = batches_.begin();
           process_iteration && it != batches_.end();)
        if (std::forward<_Predic>(pred)(*it, process_iteration)) {
          auto const erased_size = (*it)->transactions().size();
          it = batches_.erase(it);

          assert(tx_count_ >= erased_size);
          tx_count_ -= erased_size;
        } else
          ++it;

      assert(count(batches_) == tx_count_);
    }
  };

  /**
   * Contains information about all and used batches. Thread-safe.
   */
  class BatchesCache {
   public:
    using BatchesSetType = BatchesContext::BatchesSetType;
    using TimeType = shared_model::interface::types::TimestampType;

   private:
    struct BatchInfo {
      std::shared_ptr<shared_model::interface::TransactionBatch> batch;
      shared_model::interface::types::TimestampType timestamp;

      BatchInfo(
          std::shared_ptr<shared_model::interface::TransactionBatch> const &b,
          shared_model::interface::types::TimestampType const &t = 0ull)
          : batch(b), timestamp(t) {}
    };

    using MSTBatchesSetType =
        std::unordered_map<shared_model::interface::types::HashType,
                           BatchInfo,
                           shared_model::crypto::Hash::Hasher>;
    using MSTExpirationSetType =
        std::map<shared_model::interface::types::TimestampType,
                 std::shared_ptr<shared_model::interface::TransactionBatch>>;

    struct MSTState {
      MSTBatchesSetType mst_pending_;
      MSTExpirationSetType mst_expirations_;
      std::tuple<size_t, size_t> batches_and_txs_counter;

      void operator-=(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) {
        assert(std::get<0>(batches_and_txs_counter) >= 1ull);
        assert(std::get<1>(batches_and_txs_counter)
               >= batch->transactions().size());

        std::get<0>(batches_and_txs_counter) -= 1ull;
        std::get<1>(batches_and_txs_counter) -= batch->transactions().size();
      }

      void operator+=(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) {
        std::get<0>(batches_and_txs_counter) += 1ull;
        std::get<1>(batches_and_txs_counter) += batch->transactions().size();
      }

      template <typename Iterator,
                std::enable_if_t<
                    std::is_same<Iterator, MSTBatchesSetType::iterator>::value,
                    bool> = true>
      MSTBatchesSetType::iterator operator-=(Iterator const &it) {
        *this -= it->second.batch;
        mst_expirations_.erase(it->second.timestamp);
        return mst_pending_.erase(it);
      }

      template <
          typename Iterator,
          std::enable_if_t<
              std::is_same<Iterator, MSTExpirationSetType::iterator>::value,
              bool> = true>
      MSTExpirationSetType::iterator operator-=(Iterator const &it) {
        *this -= it->second;
        mst_pending_.erase(it->second->reducedHash());
        return mst_expirations_.erase(it);
      }
    };

    mutable std::shared_mutex batches_cache_cs_;
    BatchesContext batches_cache_, used_batches_cache_;

    std::shared_ptr<utils::ReadWriteObject<MSTState, std::mutex>> mst_state_;

    /**
     * MST functions
     */
    void insertMSTCache(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch);
    void removeMSTCache(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch);
    void removeMSTCache(OnDemandOrderingService::HashesSetType const &hashes);

   public:
    BatchesCache(BatchesCache const &) = delete;
    BatchesCache &operator=(BatchesCache const &) = delete;
    BatchesCache(std::chrono::minutes const &expiration_range =
                     std::chrono::minutes(24 * 60));

    uint64_t insert(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch);
    void remove(const OnDemandOrderingService::HashesSetType &hashes);
    bool isEmpty();
    uint64_t txsCount() const;
    uint64_t availableTxsCount() const;

    void forCachedBatches(std::function<void(BatchesSetType &)> const &f);

    template <typename IsProcessedFunc>
    void getTransactions(
        size_t requested_tx_amount,
        std::vector<std::shared_ptr<shared_model::interface::Transaction>>
            &collection,
        BloomFilter256 &bf,
        IsProcessedFunc &&is_processed) {
      collection.clear();
      collection.reserve(requested_tx_amount);
      bf.clear();

      std::unique_lock lock(batches_cache_cs_);
      uint32_t depth_counter = 0ul;
      batches_cache_.remove([&](auto &batch, bool &process_iteration) {
        if (std::forward<IsProcessedFunc>(is_processed)(batch))
          return true;

        auto const txs_count = batch->transactions().size();
        if (collection.size() + txs_count > requested_tx_amount) {
          ++depth_counter;
          process_iteration = (depth_counter < 8ull);
          return false;
        }

        for (auto &tx : batch->transactions())
          tx->storeBatchHash(batch->reducedHash());

        collection.insert(std::end(collection),
                          std::begin(batch->transactions()),
                          std::end(batch->transactions()));

        bf.set(batch->reducedHash());
        used_batches_cache_.insert(batch);
        return true;
      });
    }

    void processReceivedProposal(
        OnDemandOrderingService::CollectionType batches);
  };

}  // namespace iroha::ordering

#endif  // IROHA_BATCHES_CACHE_HPP
