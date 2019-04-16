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
      MOCK_METHOD2(getBlocks,
                   std::vector<BlockQuery::wBlock>(
                       shared_model::interface::types::HeightType, uint32_t));
      MOCK_METHOD1(getBlocksFrom,
                   std::vector<BlockQuery::wBlock>(
                       shared_model::interface::types::HeightType));
      MOCK_METHOD1(getTopBlocks, std::vector<BlockQuery::wBlock>(uint32_t));
      MOCK_METHOD0(getTopBlock, expected::Result<wBlock, std::string>(void));
      MOCK_METHOD1(checkTxPresence,
                   boost::optional<TxCacheStatusType>(
                       const shared_model::crypto::Hash &));
      MOCK_METHOD0(getTopBlockHeight, uint32_t(void));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_BLOCK_QUERY_HPP
