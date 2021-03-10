/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_BLOCK_QUERY_HPP
#define IROHA_MOCK_BLOCK_QUERY_HPP

#include "ametsuchi/block_query.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockBlockQuery : public BlockQuery {
     public:
      MOCK_METHOD1(
          getBlock,
          BlockQuery::BlockResult(shared_model::interface::types::HeightType));
      MOCK_METHOD(std::optional<TxCacheStatusType>,
                  checkTxPresence,
                  (const shared_model::crypto::Hash &),
                  (override));
      MOCK_METHOD0(getTopBlockHeight,
                   shared_model::interface::types::HeightType());
      MOCK_METHOD0(reloadBlockstore, void());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_BLOCK_QUERY_HPP
