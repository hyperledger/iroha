/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TX_PRESENCE_CACHE_STUB_HPP
#define IROHA_TX_PRESENCE_CACHE_STUB_HPP

#include "ametsuchi/tx_presence_cache.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Stub implementation for testing purposes. Returns T with given hash
     */
    template <typename T>
    struct TxPresenceCacheStub final : public TxPresenceCache {
      boost::optional<TxCacheStatusType> check(
          const shared_model::crypto::Hash &hash) const override {
        return boost::make_optional<TxCacheStatusType>(T{hash});
      }

      boost::optional<BatchStatusCollectionType> check(
          const shared_model::interface::TransactionBatch &batch)
          const override {
        BatchStatusCollectionType result;
        std::transform(batch.transactions().begin(),
                       batch.transactions().end(),
                       std::back_inserter(result),
                       [](auto &tx) { return T{tx->hash()}; });
        return result;
      }
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_TX_PRESENCE_CACHE_STUB_HPP
