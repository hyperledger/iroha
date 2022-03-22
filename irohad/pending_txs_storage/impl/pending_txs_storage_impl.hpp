/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PENDING_TXS_STORAGE_IMPL_HPP
#define IROHA_PENDING_TXS_STORAGE_IMPL_HPP

#include "pending_txs_storage/pending_txs_storage.hpp"

#include <list>
#include <memory>
#include <set>
#include <shared_mutex>
#include <unordered_map>

#include <boost/bimap.hpp>
#include <boost/bimap/unordered_multiset_of.hpp>
#include <boost/bimap/unordered_set_of.hpp>
#include "cryptography/hash.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace iroha {
  class PendingTransactionStorageImpl : public PendingTransactionStorage {
   public:
    using AccountIdType = shared_model::interface::types::AccountIdType;
    using HashType = shared_model::interface::types::HashType;
    using SharedTxsCollectionType =
        shared_model::interface::types::SharedTxsCollectionType;
    using TransactionBatch = shared_model::interface::TransactionBatch;
    using SharedState = std::shared_ptr<MstState>;
    using SharedBatch = std::shared_ptr<TransactionBatch>;

    SharedTxsCollectionType getPendingTransactions(
        const AccountIdType &account_id) const override;

    expected::Result<Response, ErrorCode> getPendingTransactions(
        const shared_model::interface::types::AccountIdType &account_id,
        const shared_model::interface::types::TransactionsNumberType page_size,
        const std::optional<shared_model::interface::types::HashType>
            &first_tx_hash,
        const std::optional<shared_model::interface::types::TimestampType>
            &first_tx_time = std::nullopt,
        const std::optional<shared_model::interface::types::TimestampType>
            &last_tx_time = std::nullopt) const override;

    void insertPresenceCache(
        std::shared_ptr<ametsuchi::TxPresenceCache> &cache) override;

    void removeTransaction(HashType const &hash) override;

    void updatedBatchesHandler(
        std::shared_ptr<shared_model::interface::TransactionBatch> const &batch)
        override;

    void removeBatch(const SharedBatch &batch) override;

   private:
    void removeFromStorage(const HashType &first_tx_hash,
                           const std::set<AccountIdType> &batch_creators,
                           uint64_t batch_size);

    static std::set<AccountIdType> batchCreators(const TransactionBatch &batch);

    bool isReplay(shared_model::interface::TransactionBatch const &batch);

    std::weak_ptr<ametsuchi::TxPresenceCache> presence_cache_;

    /**
     * Mutex for single-write multiple-read storage access
     */
    mutable std::shared_timed_mutex mutex_;

    /**
     * The struct represents an indexed storage of pending transactions or
     * batches for a SINGLE account.
     *
     * "batches" field contains pointers to all pending batches associated with
     * an account. Use of std::list allows us to automatically preserve their
     * mutual order.
     *
     * "index" map allows performing random access to "batches" list. Thus, we
     * can access any batch within the list in the most optimal way.
     *
     * "all transactions quantity" stores the sum of all transactions within
     * stored batches. Used for query response and memory management.
     */
    struct AccountBatches {
      using BatchPtr = std::shared_ptr<TransactionBatch>;
      using BatchesBimap = boost::bimap<
          boost::bimaps::unordered_set_of<HashType,
                                          shared_model::crypto::Hash::Hasher>,
          boost::bimaps::unordered_multiset_of<
              BatchPtr,
              shared_model::interface::BatchPointerHasher,
              shared_model::interface::BatchHashEquality>>;

      std::list<BatchPtr> batches;
      std::
          unordered_map<HashType, decltype(batches)::iterator, HashType::Hasher>
              index;
      BatchesBimap txs_to_batches;

      uint64_t all_transactions_quantity{0};
    };

    /**
     * Maps account names with its storages of pending transactions or batches.
     */
    std::unordered_map<AccountIdType, AccountBatches> storage_;
  };

}  // namespace iroha

#endif  // IROHA_PENDING_TXS_STORAGE_IMPL_HPP
