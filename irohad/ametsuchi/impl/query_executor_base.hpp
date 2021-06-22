/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_EXECUTOR_BASE_HPP
#define IROHA_QUERY_EXECUTOR_BASE_HPP

#include "ametsuchi/query_executor.hpp"

#include "logger/logger_fwd.hpp"

namespace shared_model {
  namespace interface {
    class QueryResponseFactory;
  }  // namespace interface
}  // namespace shared_model

namespace iroha::ametsuchi {

  class SpecificQueryExecutor;

  class QueryExecutorBase : public QueryExecutor {
   public:
    QueryExecutorBase(
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<SpecificQueryExecutor> specific_query_executor,
        logger::LoggerPtr log);

    QueryExecutorResult validateAndExecute(
        const shared_model::interface::Query &query,
        const bool validate_signatories) override;

    bool validate(const shared_model::interface::BlocksQuery &query,
                  const bool validate_signatories) override;

    virtual bool validateSignatures(
        const shared_model::interface::Query &query) = 0;
    virtual bool validateSignatures(
        const shared_model::interface::BlocksQuery &query) = 0;

   protected:
    std::shared_ptr<SpecificQueryExecutor> specific_query_executor_;
    std::shared_ptr<shared_model::interface::QueryResponseFactory>
        query_response_factory_;
    logger::LoggerPtr log_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_QUERY_EXECUTOR_HPP
