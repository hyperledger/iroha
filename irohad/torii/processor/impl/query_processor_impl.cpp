/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/processor/query_processor_impl.hpp"

#include "common/bind.hpp"
#include "common/result.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/query_responses/block_query_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace torii {

    QueryProcessorImpl::QueryProcessorImpl(
        std::shared_ptr<ametsuchi::Storage> storage,
        std::shared_ptr<ametsuchi::QueryExecutorFactory> qry_exec,
        std::shared_ptr<iroha::PendingTransactionStorage> pending_transactions,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        logger::LoggerPtr log)
        : storage_{std::move(storage)},
          qry_exec_{std::move(qry_exec)},
          pending_transactions_{std::move(pending_transactions)},
          response_factory_{std::move(response_factory)},
          log_{std::move(log)} {}

    iroha::expected::Result<
        std::unique_ptr<shared_model::interface::QueryResponse>,
        std::string>
    QueryProcessorImpl::queryHandle(const shared_model::interface::Query &qry) {
      return qry_exec_->createQueryExecutor(pending_transactions_,
                                            response_factory_)
          | [&](auto &&executor) {
              return executor->validateAndExecute(qry, true);
            };
    }

    iroha::expected::Result<void, std::string>
    QueryProcessorImpl::blocksQueryHandle(
        const shared_model::interface::BlocksQuery &qry) {
      auto maybe_query_executor = qry_exec_->createQueryExecutor(
          pending_transactions_, response_factory_);
      if (iroha::expected::hasError(maybe_query_executor)) {
        return maybe_query_executor.assumeError();
      }
      if (not maybe_query_executor.assumeValue()->validate(qry, true)) {
        return "stateful invalid";
      }
      return iroha::expected::makeValue();
    }

  }  // namespace torii
}  // namespace iroha
