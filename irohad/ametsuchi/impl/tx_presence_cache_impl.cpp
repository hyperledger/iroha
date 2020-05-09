/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/tx_presence_cache_impl.hpp"

#include "common/bind.hpp"
#include "common/visitor.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/transaction.hpp"

namespace iroha {
  namespace ametsuchi {
    TxPresenceCacheImpl::TxPresenceCacheImpl(std::shared_ptr<Storage> storage)
        : storage_(std::move(storage)) {}

    std::optional<TxCacheStatusType> TxPresenceCacheImpl::check(
        const shared_model::crypto::Hash &hash) const {
      auto res = memory_cache_.findItem(hash);
      if (res) {
        return *res;
      }
      return checkInStorage(hash);
    }

    std::optional<TxPresenceCache::BatchStatusCollectionType>
    TxPresenceCacheImpl::check(
        const shared_model::interface::TransactionBatch &batch) const {
      TxPresenceCache::BatchStatusCollectionType batch_statuses;
      for (const auto &tx : batch.transactions()) {
        if (auto status = check(tx->hash())) {
          batch_statuses.emplace_back(*status);
        } else {
          return std::nullopt;
        }
      }
      return batch_statuses;
    }

    std::optional<TxCacheStatusType> TxPresenceCacheImpl::checkInStorage(
        const shared_model::crypto::Hash &hash) const {
      auto block_query = storage_->getBlockQuery();
      if (not block_query) {
        return std::nullopt;
      }
      return block_query->checkTxPresence(hash) |
          [this, &hash](const auto &status) {
            std::visit(make_visitor(
                           [](const tx_cache_status_responses::Missing &) {
                             // don't put this hash into cache since "Missing"
                             // can become "Committed" or "Rejected" later
                           },
                           [this, &hash](const auto &status) {
                             memory_cache_.addItem(hash, status);
                           }),
                       status);
            return status;
          };
    }
  }  // namespace ametsuchi
}  // namespace iroha
