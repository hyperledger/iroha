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
      BatchObservable expired_batch,
      PreparedTransactionsObservable prepared_txs) {
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
    prepared_transactions_subscription_ = prepared_txs.subscribe(
        [this](const PreparedTransactionDescriptor &prepared_transaction) {
          this->removeBatch(prepared_transaction);
        });
  }

  PendingTransactionStorageImpl::~PendingTransactionStorageImpl() {
    updated_batches_subscription_.unsubscribe();
    prepared_batch_subscription_.unsubscribe();
    expired_batch_subscription_.unsubscribe();
    prepared_transactions_subscription_.unsubscribe();
  }

  PendingTransactionStorageImpl::SharedTxsCollectionType
  PendingTransactionStorageImpl::getPendingTransactions(
      const AccountIdType &account_id) const {
    std::shared_lock<std::shared_timed_mutex> lock(mutex_);
    auto account_batches_iterator = storage_.find(account_id);
    if (storage_.end() != account_batches_iterator) {
      SharedTxsCollectionType result;
      for (const auto &batch : account_batches_iterator->second.batches) {
        auto &txs = batch->transactions();
        result.insert(result.end(), txs.begin(), txs.end());
      }
      return result;
    }
    return {};
  }

  expected::Result<PendingTransactionStorage::Response,
                   PendingTransactionStorage::ErrorCode>
  PendingTransactionStorageImpl::getPendingTransactions(
      const shared_model::interface::types::AccountIdType &account_id,
      const shared_model::interface::types::TransactionsNumberType page_size,
      const boost::optional<shared_model::interface::types::HashType>
          &first_tx_hash) const {
    BOOST_ASSERT_MSG(page_size > 0, "Page size has to be positive");
    std::shared_lock<std::shared_timed_mutex> lock(mutex_);
    auto account_batches_iterator = storage_.find(account_id);
    if (storage_.end() == account_batches_iterator) {
      if (first_tx_hash) {
        return iroha::expected::makeError(
            PendingTransactionStorage::ErrorCode::kNotFound);
      } else {
        return iroha::expected::makeValue(
            PendingTransactionStorage::Response{});
      }
    }
    auto &account_batches = account_batches_iterator->second;
    auto batch_iterator = account_batches.batches.begin();
    if (first_tx_hash) {
      auto index_iterator = account_batches.index.find(*first_tx_hash);
      if (account_batches.index.end() == index_iterator) {
        return iroha::expected::makeError(
            PendingTransactionStorage::ErrorCode::kNotFound);
      }
      batch_iterator = index_iterator->second;
    }
    BOOST_ASSERT_MSG(account_batches.batches.end() != batch_iterator,
                     "Empty account batches entry was not removed");

    PendingTransactionStorage::Response response;
    response.all_transactions_size = account_batches.all_transactions_quantity;
    auto remaining_space = page_size;
    while (account_batches.batches.end() != batch_iterator
           and remaining_space
               >= batch_iterator->get()->transactions().size()) {
      auto &txs = batch_iterator->get()->transactions();
      response.transactions.insert(
          response.transactions.end(), txs.begin(), txs.end());
      remaining_space -= txs.size();
      ++batch_iterator;
    }
    if (account_batches.batches.end() != batch_iterator) {
      auto &txs = batch_iterator->get()->transactions();
      shared_model::interface::PendingTransactionsPageResponse::BatchInfo
          next_batch_info{txs.front()->hash(),
                          next_batch_info.batch_size = txs.size()};
      response.next_batch_info = std::move(next_batch_info);
    }
    return iroha::expected::makeValue(std::move(response));
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
    // need to test performance somehow - where to put the lock
    std::unique_lock<std::shared_timed_mutex> lock(mutex_);
    updated_batches->iterateBatches([this](const auto &batch) {
      auto first_tx_hash = batch->transactions().front()->hash();
      auto batch_creators = batchCreators(*batch);
      auto batch_size = batch->transactions().size();
      for (const auto &creator : batch_creators) {
        auto account_batches_iterator = storage_.find(creator);
        if (storage_.end() == account_batches_iterator) {
          auto insertion_result = storage_.emplace(
              creator, PendingTransactionStorageImpl::AccountBatches{});
          BOOST_ASSERT(insertion_result.second);
          account_batches_iterator = insertion_result.first;
        }

        auto &account_batches = account_batches_iterator->second;
        auto index_iterator = account_batches.index.find(first_tx_hash);
        if (index_iterator == account_batches.index.end()) {
          // inserting the batch
          account_batches.all_transactions_quantity += batch_size;
          account_batches.batches.push_back(batch);
          auto inserted_batch_iterator =
              std::prev(account_batches.batches.end());
          account_batches.index.emplace(first_tx_hash, inserted_batch_iterator);
        } else {
          // updating batch
          auto &account_batch = index_iterator->second;
          *account_batch = batch;
        }
      }
    });
  }

  inline void PendingTransactionStorageImpl::removeFromStorage(
      const HashType &first_tx_hash,
      const std::set<AccountIdType> &batch_creators,
      uint64_t batch_size) {
    // outer scope has to acquire unique lock over mutex_
    for (const auto &creator : batch_creators) {
      auto account_batches_iterator = storage_.find(creator);
      if (account_batches_iterator != storage_.end()) {
        auto &account_batches = account_batches_iterator->second;
        auto index_iterator = account_batches.index.find(first_tx_hash);
        if (index_iterator != account_batches.index.end()) {
          auto &batch_iterator = index_iterator->second;
          BOOST_ASSERT(batch_iterator != account_batches.batches.end());
          account_batches.batches.erase(batch_iterator);
          account_batches.index.erase(index_iterator);
          account_batches.all_transactions_quantity -= batch_size;
        }
        if (0 == account_batches.all_transactions_quantity) {
          storage_.erase(account_batches_iterator);
        }
      }
    }
  }

  void PendingTransactionStorageImpl::removeBatch(const SharedBatch &batch) {
    auto creators = batchCreators(*batch);
    auto first_tx_hash = batch->transactions().front()->hash();
    auto batch_size = batch->transactions().size();
    std::unique_lock<std::shared_timed_mutex> lock(mutex_);
    removeFromStorage(first_tx_hash, creators, batch_size);
  }

  void PendingTransactionStorageImpl::removeBatch(
      const PreparedTransactionDescriptor &prepared_transaction) {
    boost::optional<std::set<AccountIdType>> creators = boost::none;
    boost::optional<uint64_t> batch_size = boost::none;
    auto &creator_id = prepared_transaction.first;
    auto &first_transaction_hash = prepared_transaction.second;
    {
      std::shared_lock<std::shared_timed_mutex> lock(mutex_);
      auto account_batches_iterator = storage_.find(creator_id);
      if (account_batches_iterator != storage_.end()) {
        auto &account_batches = account_batches_iterator->second;
        auto index_iterator =
            account_batches.index.find(first_transaction_hash);
        if (index_iterator != account_batches.index.end()) {
          auto &batch_iterator = index_iterator->second;
          BOOST_ASSERT(batch_iterator != account_batches.batches.end());
          creators = batchCreators(**batch_iterator);
          batch_size = boost::size((*batch_iterator)->transactions());
        }
      }
    }
    if (creators and batch_size) {
      std::unique_lock<std::shared_timed_mutex> lock(mutex_);
      removeFromStorage(first_transaction_hash, *creators, *batch_size);
    }
  }

}  // namespace iroha
