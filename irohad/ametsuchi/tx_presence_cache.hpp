/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TX_PRESENCE_CACHE_HPP
#define IROHA_TX_PRESENCE_CACHE_HPP

#include <vector>

#include <boost/optional.hpp>
#include "ametsuchi/tx_cache_response.hpp"

namespace shared_model {
  namespace crypto {
    class Hash;
  }  // namespace crypto

  namespace interface {
    class TransactionBatch;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    /**
     * Class is responsible for checking transaction status in the ledger
     */
    class TxPresenceCache {
     public:
      /**
       * Check transaction status by hash
       * @return transaction status if storage query was successful, boost::none
       * otherwise
       */
      virtual boost::optional<TxCacheStatusType> check(
          const shared_model::crypto::Hash &hash) const = 0;

      /// response type which reflects status of each transaction in a batch
      using BatchStatusCollectionType = std::vector<TxCacheStatusType>;

      /**
       * Check batch status
       * @return a collection with answers about each transaction in the batch
       * if storage queries were successful, boost::none otherwise
       */
      virtual boost::optional<BatchStatusCollectionType> check(
          const shared_model::interface::TransactionBatch &batch) const = 0;

      // TODO: 09/11/2018 @muratovv add method for processing collection of
      // batches IR-1857

      virtual ~TxPresenceCache() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_TX_PRESENCE_CACHE_HPP
