/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_QUERY_PROCESSOR_HPP
#define IROHA_MOCK_QUERY_PROCESSOR_HPP

#include "torii/processor/query_processor.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace torii {

    class MockQueryProcessor : public QueryProcessor {
     public:
      MOCK_METHOD1(queryHandle,
                   iroha::expected::Result<
                       std::unique_ptr<shared_model::interface::QueryResponse>,
                       std::string>(const shared_model::interface::Query &));
      MOCK_METHOD((iroha::expected::Result<void, std::string>),
                  blocksQueryHandle,
                  (shared_model::interface::BlocksQuery const &),
                  (override));
    };

  }  // namespace torii
}  // namespace iroha

#endif  // IROHA_MOCK_QUERY_PROCESSOR_HPP
