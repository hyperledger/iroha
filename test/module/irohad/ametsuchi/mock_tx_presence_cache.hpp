/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_TX_PRESENCE_CACHE_HPP
#define IROHA_MOCK_TX_PRESENCE_CACHE_HPP

#include "ametsuchi/tx_presence_cache.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockTxPresenceCache : public TxPresenceCache {
     public:
      MOCK_CONST_METHOD1(check,
                         boost::optional<TxCacheStatusType>(
                             const shared_model::crypto::Hash &hash));

      MOCK_CONST_METHOD1(
          check,
          boost::optional<TxPresenceCache::BatchStatusCollectionType>(
              const shared_model::interface::TransactionBatch &));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_TX_PRESENCE_CACHE_HPP
