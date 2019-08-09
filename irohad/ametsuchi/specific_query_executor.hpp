/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_SPECIFIC_QUERY_EXECUTOR_HPP
#define IROHA_AMETSUCHI_SPECIFIC_QUERY_EXECUTOR_HPP

#include <memory>

#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"

namespace shared_model {
  namespace interface {
    class Query;
    class QueryResponse;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    using QueryExecutorResult =
        std::unique_ptr<shared_model::interface::QueryResponse>;

    /**
     * Executes query variant types
     */
    class SpecificQueryExecutor {
     public:
      virtual ~SpecificQueryExecutor() = default;

      virtual QueryExecutorResult execute(
          const shared_model::interface::Query &qry) = 0;

      virtual bool hasAccountRolePermission(
          shared_model::interface::permissions::Role permission,
          const std::string &account_id) const = 0;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_SPECIFIC_QUERY_EXECUTOR_HPP
