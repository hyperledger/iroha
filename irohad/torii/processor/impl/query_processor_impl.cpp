/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/processor/query_processor_impl.hpp"

#include <boost/range/size.hpp>
#include "common/bind.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/query_responses/block_query_response.hpp"
#include "interfaces/query_responses/block_response.hpp"
#include "interfaces/query_responses/query_response.hpp"
#include "logger/logger.hpp"
#include "validation/utils.hpp"

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

    std::unique_ptr<shared_model::interface::QueryResponse>
    QueryProcessorImpl::queryHandle(const shared_model::interface::Query &qry) {
      auto executor = qry_exec_->createQueryExecutor(pending_transactions_,
                                                     response_factory_);
      if (not executor) {
        log_->error("Cannot create query executor");
        return nullptr;
      }

      return executor.value()->validateAndExecute(qry, true);
    }

    rxcpp::observable<
        std::shared_ptr<shared_model::interface::BlockQueryResponse>>
    QueryProcessorImpl::blocksQueryHandle(
        const shared_model::interface::BlocksQuery &qry) {
      auto exec = qry_exec_->createQueryExecutor(pending_transactions_,
                                                 response_factory_);
      if (not exec or not(exec | [&qry](const auto &executor) {
            return executor->validate(qry, true);
          })) {
        std::shared_ptr<shared_model::interface::BlockQueryResponse> response =
            response_factory_->createBlockQueryResponse("stateful invalid");
        return rxcpp::observable<>::just(std::move(response));
      }
      return blocks_query_subject_.get_observable();
    }

  }  // namespace torii
}  // namespace iroha
