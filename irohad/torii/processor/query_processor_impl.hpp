/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_PROCESSOR_IMPL_HPP
#define IROHA_QUERY_PROCESSOR_IMPL_HPP

#include "torii/processor/query_processor.hpp"

#include <rxcpp/rx-lite.hpp>
#include "ametsuchi/storage.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "logger/logger_fwd.hpp"
#include "main/subscription.hpp"

namespace iroha {
  namespace torii {

    /**
     * QueryProcessorImpl provides implementation of QueryProcessor
     */
    class QueryProcessorImpl
        : public QueryProcessor,
          public std::enable_shared_from_this<QueryProcessorImpl> {
     public:
      QueryProcessorImpl(
          std::shared_ptr<ametsuchi::Storage> storage,
          std::shared_ptr<ametsuchi::QueryExecutorFactory> qry_exec,
          std::shared_ptr<iroha::PendingTransactionStorage>
              pending_transactions,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              response_factory,
          logger::LoggerPtr log);
      void initialize();

      iroha::expected::Result<
          std::unique_ptr<shared_model::interface::QueryResponse>,
          std::string>
      queryHandle(const shared_model::interface::Query &qry) override;

      rxcpp::observable<
          std::shared_ptr<shared_model::interface::BlockQueryResponse>>
      blocksQueryHandle(
          const shared_model::interface::BlocksQuery &qry) override;

     private:
      rxcpp::subjects::subject<
          std::shared_ptr<shared_model::interface::BlockQueryResponse>>
          blocks_query_subject_;
      std::shared_ptr<ametsuchi::Storage> storage_;
      std::shared_ptr<ametsuchi::QueryExecutorFactory> qry_exec_;
      std::shared_ptr<iroha::PendingTransactionStorage> pending_transactions_;
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          response_factory_;

      std::shared_ptr<
          BaseSubscriber<bool,
                         std::shared_ptr<const shared_model::interface::Block>>>
          block_subscription_;

      logger::LoggerPtr log_;
    };

  }  // namespace torii
}  // namespace iroha

#endif  // IROHA_QUERY_PROCESSOR_IMPL_HPP
