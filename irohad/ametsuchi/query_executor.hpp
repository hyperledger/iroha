/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_EXECUTOR_HPP
#define IROHA_QUERY_EXECUTOR_HPP

#include <memory>

namespace shared_model {
  namespace interface {
    class Query;
    class BlocksQuery;
    class QueryResponse;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    using QueryExecutorResult =
        std::unique_ptr<shared_model::interface::QueryResponse>;

    class QueryExecutor {
     public:
      virtual ~QueryExecutor() = default;
      /**
       * Execute and validate query.
       * @param query to validate and execute
       * @param validate_signatories - if signatories should be validated
       * @return pointer to query response
       */
      virtual QueryExecutorResult validateAndExecute(
          const shared_model::interface::Query &query,
          const bool validate_signatories) = 0;

      /**
       * Perform BlocksQuery validation
       * @param query to validate
       * @param validate_signatories - if signatories should be validated
       * @return true if valid, false otherwise
       */
      virtual bool validate(const shared_model::interface::BlocksQuery &query,
                            const bool validate_signatories) = 0;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_QUERY_EXECUTOR_HPP
