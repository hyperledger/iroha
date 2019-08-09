/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_SPECIFIC_QUERY_EXECUTOR_HPP
#define IROHA_MOCK_SPECIFIC_QUERY_EXECUTOR_HPP

#include "ametsuchi/specific_query_executor.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockSpecificQueryExecutor : public SpecificQueryExecutor {
     public:
      MOCK_METHOD1(execute,
                   QueryExecutorResult(const shared_model::interface::Query &));

      MOCK_CONST_METHOD2(
          hasAccountRolePermission,
          bool(shared_model::interface::permissions::Role permission,
               const std::string &account_id));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_SPECIFIC_QUERY_EXECUTOR_HPP
