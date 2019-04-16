/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PENDING_TXS_STORAGE_IMPL_HPP
#define IROHA_PENDING_TXS_STORAGE_IMPL_HPP

#include <set>
#include <shared_mutex>
#include <unordered_map>
#include <unordered_set>

#include <rxcpp/rx.hpp>
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "pending_txs_storage/pending_txs_storage.hpp"

namespace iroha {

  class MstState;

  class PendingTransactionStorageImpl : public PendingTransactionStorage {
   public:
    using AccountIdType = shared_model::interface::types::AccountIdType;
    using HashType = shared_model::interface::types::HashType;
    using SharedTxsCollectionType =
        shared_model::interface::types::SharedTxsCollectionType;
    using TransactionBatch = shared_model::interface::TransactionBatch;
    using SharedState = std::shared_ptr<MstState>;
    using SharedBatch = std::shared_ptr<TransactionBatch>;
    using StateObservable = rxcpp::observable<SharedState>;
    using BatchObservable = rxcpp::observable<SharedBatch>;

    PendingTransactionStorageImpl(StateObservable updated_batches,
                                  BatchObservable prepared_batch,
                                  BatchObservable expired_batch);

    ~PendingTransactionStorageImpl() override;

    SharedTxsCollectionType getPendingTransactions(
        const AccountIdType &account_id) const override;

   private:
    void updatedBatchesHandler(const SharedState &updated_batches);

    void removeBatch(const SharedBatch &batch);

    static std::set<AccountIdType> batchCreators(const TransactionBatch &batch);

    /**
     * Subscriptions on MST events
     */
    rxcpp::composite_subscription updated_batches_subscription_;
    rxcpp::composite_subscription prepared_batch_subscription_;
    rxcpp::composite_subscription expired_batch_subscription_;

    /**
     * Mutex for single-write multiple-read storage access
     */
    mutable std::shared_timed_mutex mutex_;

    /**
     * Storage is composed of two maps:
     * Indices map contains relations of accounts and batch hashes. For each
     * account there are listed hashes of batches, where the account has created
     * at least one transaction.
     *
     * Batches map is used for storing and fast access to batches via batch
     * hashes.
     */
    struct {
      std::unordered_map<AccountIdType,
                         std::unordered_set<HashType, HashType::Hasher>>
          index;
      std::unordered_map<HashType,
                         std::shared_ptr<TransactionBatch>,
                         HashType::Hasher>
          batches;
    } storage_;
  };

}  // namespace iroha

#endif  // IROHA_PENDING_TXS_STORAGE_IMPL_HPP
