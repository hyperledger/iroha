/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TX_PRESENCE_CACHE_IMPL_HPP
#define IROHA_TX_PRESENCE_CACHE_IMPL_HPP

#include "ametsuchi/storage.hpp"
#include "ametsuchi/tx_presence_cache.hpp"
#include "cache/cache.hpp"

namespace iroha {
  namespace ametsuchi {

    class TxPresenceCacheImpl : public TxPresenceCache {
     public:
      explicit TxPresenceCacheImpl(std::shared_ptr<Storage> storage);

      boost::optional<TxCacheStatusType> check(
          const shared_model::crypto::Hash &hash) const override;

      boost::optional<BatchStatusCollectionType> check(
          const shared_model::interface::TransactionBatch &batch)
          const override;

     private:
      /**
       * Performs an actual storage request about hash status
       * @param hash to check
       * @return hash status if storage query was successful, boost::none
       * otherwise
       */
      boost::optional<TxCacheStatusType> checkInStorage(
          const shared_model::crypto::Hash &hash) const;

      std::shared_ptr<Storage> storage_;
      mutable cache::Cache<shared_model::crypto::Hash,
                           TxCacheStatusType,
                           shared_model::crypto::Hash::Hasher>
          memory_cache_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_TX_PRESENCE_CACHE_IMPL_HPP
