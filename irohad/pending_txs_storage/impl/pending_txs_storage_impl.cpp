/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "pending_txs_storage/impl/pending_txs_storage_impl.hpp"

#include <mutex>

#include "ametsuchi/tx_presence_cache_utils.hpp"
#include "interfaces/transaction.hpp"

using iroha::PendingTransactionStorageImpl;

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

iroha::expected::Result<PendingTransactionStorageImpl::Response,
                        PendingTransactionStorageImpl::ErrorCode>
PendingTransactionStorageImpl::getPendingTransactions(
    const shared_model::interface::types::AccountIdType &account_id,
    const shared_model::interface::types::TransactionsNumberType page_size,
    const std::optional<shared_model::interface::types::HashType>
        &first_tx_hash,
    const std::optional<shared_model::interface::types::TimestampType>
        &first_tx_time,
    const std::optional<shared_model::interface::types::TimestampType>
        &last_tx_time) const {
  BOOST_ASSERT_MSG(page_size > 0, "Page size has to be positive");
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  auto account_batches_iterator = storage_.find(account_id);
  if (storage_.end() == account_batches_iterator) {
    if (first_tx_hash) {
      return iroha::expected::makeError(
          PendingTransactionStorage::ErrorCode::kNotFound);
    } else {
      return iroha::expected::makeValue(PendingTransactionStorage::Response{});
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
  while (account_batches.batches.end() != batch_iterator
         and (response.transactions.size()
              + (*batch_iterator)->transactions().size())
             <= page_size) {
    auto &txs = batch_iterator->get()->transactions();
    std::copy_if(txs.begin(),
                 txs.end(),
                 std::back_inserter(response.transactions),
                 [&first_tx_time, &last_tx_time](auto const &tx) {
                   auto const ts = tx->createdTime();
                   return (!first_tx_time || ts >= *first_tx_time)
                       && (!last_tx_time || ts <= *last_tx_time);
                 });
    ++batch_iterator;
  }
  if (account_batches.batches.end() != batch_iterator) {
    shared_model::interface::PendingTransactionsPageResponse::BatchInfo
        next_batch_info;
    auto &txs = batch_iterator->get()->transactions();
    next_batch_info.first_tx_hash = txs.front()->hash();
    next_batch_info.batch_size = txs.size();
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
    std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
  // need to test performance somehow - where to put the lock
  std::unique_lock<std::shared_timed_mutex> lock(mutex_);
  if (isReplay(*batch)) {
    return;
  }

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
      auto inserted_batch_iterator = std::prev(account_batches.batches.end());
      account_batches.index.emplace(first_tx_hash, inserted_batch_iterator);
      for (auto &tx : batch->transactions()) {
        account_batches.txs_to_batches.insert({tx->hash(), batch});
      }
    } else {
      // updating batch
      auto &account_batch = index_iterator->second;
      *account_batch = batch;
    }
  }
}

bool PendingTransactionStorageImpl::isReplay(
    shared_model::interface::TransactionBatch const &batch) {
  auto cache_ptr = presence_cache_.lock();
  if (!cache_ptr) {
    return false;
  }

  auto cache_presence = cache_ptr->check(batch);
  if (!cache_presence) {
    return false;
  }

  return std::any_of(cache_presence->begin(),
                     cache_presence->end(),
                     &ametsuchi::isAlreadyProcessed);
}

void PendingTransactionStorageImpl::insertPresenceCache(
    std::shared_ptr<ametsuchi::TxPresenceCache> &cache) {
  assert(!!cache);
  presence_cache_ = cache;
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
        account_batches.txs_to_batches.right.erase(*batch_iterator);
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

void PendingTransactionStorageImpl::removeTransaction(HashType const &hash) {
  std::shared_lock<std::shared_timed_mutex> read_lock(mutex_);
  for (auto &p : storage_) {
    auto &txs_index = p.second.txs_to_batches;
    auto it = txs_index.left.find(hash);
    if (txs_index.left.end() != it) {
      auto batch = it->second;
      assert(!!batch);

      auto const &transactions = batch->transactions();
      auto const &first_transaction_hash = transactions.front()->hash();
      auto const &creators = batchCreators(*batch);
      auto batch_size = transactions.size();
      read_lock.unlock();
      std::unique_lock<std::shared_timed_mutex> write_lock(mutex_);
      removeFromStorage(first_transaction_hash, creators, batch_size);
      return;
    }
  }
}
