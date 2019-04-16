/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MST_STORAGE_GUARD_HPP
#define IROHA_MST_STORAGE_GUARD_HPP

#include <atomic>

#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "multi_sig_transactions/mst_types.hpp"
#include "storage_shared_limit/storage_limit.hpp"

namespace iroha {

  class BatchStorageLimitByTxs : public StorageLimit<BatchPtr> {
   public:
    explicit BatchStorageLimitByTxs(size_t txs_limit) : txs_limit_(txs_limit) {}

    bool addIfAllowed(const BatchPtr &batch) override {
      const auto added_txs_quantity = batch->transactions().size();

      size_t current_txs_quantity;
      size_t new_txs_quantity;
      do {
        current_txs_quantity = txs_quantity_.load(std::memory_order_relaxed);
        new_txs_quantity = current_txs_quantity + added_txs_quantity;
        if (new_txs_quantity > txs_limit_) {
          return false;
        }
      } while (not std::atomic_compare_exchange_weak_explicit(
          &txs_quantity_,
          &current_txs_quantity,
          new_txs_quantity,
          std::memory_order_relaxed,
          std::memory_order_relaxed));
      assert(txs_limit_ >= txs_quantity_.load(std::memory_order_relaxed));
      return true;
    }

    void remove(const BatchPtr &batch) override {
      const size_t extracted_txs = batch->transactions().size();
      assert(txs_quantity_.load(std::memory_order_relaxed) >= extracted_txs);
      txs_quantity_.fetch_sub(extracted_txs, std::memory_order_relaxed);
    }

    size_t transactionsQuantity() const {
      return txs_quantity_;
    }

   private:
    const size_t txs_limit_;
    std::atomic<size_t> txs_quantity_{0};
  };

}  // namespace iroha

#endif  // IROHA_MST_STORAGE_GUARD_HPP
