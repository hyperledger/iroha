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
      MOCK_METHOD1(checkTxPresence,
                   boost::optional<TxCacheStatusType>(
                       const shared_model::crypto::Hash &));
      MOCK_METHOD0(getTopBlockHeight,
                   shared_model::interface::types::HeightType());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_BLOCK_QUERY_HPP
