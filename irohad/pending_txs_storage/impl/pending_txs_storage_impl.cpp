/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pending_txs_storage/impl/pending_txs_storage_impl.hpp"

#include "interfaces/transaction.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"

namespace iroha {

  PendingTransactionStorageImpl::PendingTransactionStorageImpl(
      StateObservable updated_batches,
      BatchObservable prepared_batch,
      BatchObservable expired_batch) {
    updated_batches_subscription_ =
        updated_batches.subscribe([this](const SharedState &batches) {
          this->updatedBatchesHandler(batches);
        });
    prepared_batch_subscription_ =
        prepared_batch.subscribe([this](const SharedBatch &preparedBatch) {
          this->removeBatch(preparedBatch);
        });
    expired_batch_subscription_ =
        expired_batch.subscribe([this](const SharedBatch &expiredBatch) {
          this->removeBatch(expiredBatch);
        });
  }

  PendingTransactionStorageImpl::~PendingTransactionStorageImpl() {
    updated_batches_subscription_.unsubscribe();
    prepared_batch_subscription_.unsubscribe();
    expired_batch_subscription_.unsubscribe();
  }

  PendingTransactionStorageImpl::SharedTxsCollectionType
  PendingTransactionStorageImpl::getPendingTransactions(
      const AccountIdType &account_id) const {
    std::shared_lock<std::shared_timed_mutex> lock(mutex_);
    auto creator_it = storage_.index.find(account_id);
    if (storage_.index.end() != creator_it) {
      auto &batch_hashes = creator_it->second;
      SharedTxsCollectionType result;
      auto &batches = storage_.batches;
      for (const auto &batch_hash : batch_hashes) {
        auto batch_it = batches.find(batch_hash);
        if (batches.end() != batch_it) {
          auto &txs = batch_it->second->transactions();
          result.insert(result.end(), txs.begin(), txs.end());
        }
      }
      return result;
    }
    return {};
  }

  std::set<PendingTransactionStorageImpl::AccountIdType>
  PendingTransactionStorageImpl::batchCreators(const TransactionBatch &batch) {
    std::set<AccountIdType> creators;
    for (const auto &transaction : batch.transactions()) {
      creators.insert(transaction->creatorAccountId());
    }
    return creators;
  }

  void PendingTransactionStorageImpl::updatedBatchesHandler(
      const SharedState &updated_batches) {
    std::unique_lock<std::shared_timed_mutex> lock(mutex_);
    updated_batches->iterateBatches([this](const auto &batch) {
      auto hash = batch->reducedHash();
      auto it = storage_.batches.find(hash);
      if (storage_.batches.end() == it) {
        for (const auto &creator : batchCreators(*batch)) {
          storage_.index[creator].insert(hash);
        }
      }
      storage_.batches[hash] = batch;
    });
  }

  void PendingTransactionStorageImpl::removeBatch(const SharedBatch &batch) {
    auto creators = batchCreators(*batch);
    auto hash = batch->reducedHash();
    std::unique_lock<std::shared_timed_mutex> lock(mutex_);
    storage_.batches.erase(hash);
    for (const auto &creator : creators) {
      auto &index = storage_.index;
      auto index_it = index.find(creator);
      if (index.end() != index_it) {
        auto &creator_set = index_it->second;
        creator_set.erase(hash);
      }
    }
  }

}  // namespace iroha
