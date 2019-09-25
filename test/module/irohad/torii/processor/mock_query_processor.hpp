/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_QUERY_PROCESSOR_HPP
#define IROHA_MOCK_QUERY_PROCESSOR_HPP

#include "torii/processor/query_processor.hpp"

#include <gmock/gmock.h>
#include <rxcpp/rx-lite.hpp>

namespace iroha {
  namespace torii {

    class MockQueryProcessor : public QueryProcessor {
     public:
      MOCK_METHOD1(queryHandle,
                   std::unique_ptr<shared_model::interface::QueryResponse>(
                       const shared_model::interface::Query &));
      MOCK_METHOD1(
          blocksQueryHandle,
          rxcpp::observable<
              std::shared_ptr<shared_model::interface::BlockQueryResponse>>(
              const shared_model::interface::BlocksQuery &));
    };

  }  // namespace torii
}  // namespace iroha

#endif  // IROHA_MOCK_QUERY_PROCESSOR_HPP
