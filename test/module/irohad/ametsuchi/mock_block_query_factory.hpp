/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_BLOCK_QUERY_FACTORY_HPP
#define IROHA_MOCK_BLOCK_QUERY_FACTORY_HPP

#include "ametsuchi/block_query_factory.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockBlockQueryFactory : public BlockQueryFactory {
     public:
      MOCK_CONST_METHOD0(createBlockQuery,
                         boost::optional<std::shared_ptr<BlockQuery>>());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_BLOCK_QUERY_FACTORY_HPP
