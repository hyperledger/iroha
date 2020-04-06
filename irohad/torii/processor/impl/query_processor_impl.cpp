/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/processor/query_processor_impl.hpp"

#include <boost/range/size.hpp>
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
          log_{std::move(log)} {
      storage_->on_commit().subscribe(
          [this](std::shared_ptr<const shared_model::interface::Block> block) {
            auto block_response =
                response_factory_->createBlockQueryResponse(block);
            blocks_query_subject_.get_subscriber().on_next(
                std::move(block_response));
          });
    }

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

    rxcpp::observable<
        std::shared_ptr<shared_model::interface::BlockQueryResponse>>
    QueryProcessorImpl::blocksQueryHandle(
        const shared_model::interface::BlocksQuery &qry) {
      using shared_model::interface::BlockQueryResponse;
      auto make_error = [this](std::string &&error)
          -> rxcpp::observable<std::shared_ptr<BlockQueryResponse>> {
        std::shared_ptr<BlockQueryResponse> response =
            response_factory_->createBlockQueryResponse(std::move(error));
        return rxcpp::observable<>::just(std::move(response));
      };

      return qry_exec_
          ->createQueryExecutor(pending_transactions_, response_factory_)
          .match(
              [&](const auto &executor) {
                if (executor.value->validate(qry, true)) {
                  return blocks_query_subject_.get_observable();
                }
                return make_error("stateful invalid");
              },
              [&](const auto &e) {
                log_->error("Could not validate query: {}", e.error);
                return make_error("Internal error during query validation.");
              });
    }

  }  // namespace torii
}  // namespace iroha
