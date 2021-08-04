/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_QUERY_EXECUTOR_HPP
#define IROHA_ROCKSDB_QUERY_EXECUTOR_HPP

#include "ametsuchi/impl/query_executor_base.hpp"

#include "logger/logger_fwd.hpp"

namespace shared_model {
  namespace interface {
    class QueryResponseFactory;
  }  // namespace interface
}  // namespace shared_model

namespace iroha::ametsuchi {

  class RocksDbSpecificQueryExecutor;
  struct RocksDBContext;

  class RocksDbQueryExecutor : public QueryExecutorBase {
   public:
    RocksDbQueryExecutor(
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<RocksDbSpecificQueryExecutor> specific_query_executor,
        logger::LoggerPtr log);

    bool validateSignatures(
        const shared_model::interface::Query &query) override;
    bool validateSignatures(
        const shared_model::interface::BlocksQuery &query) override;

   private:
    template <class Q>
    bool validateSignaturesImpl(const Q &query);
    std::shared_ptr<RocksDBContext> tx_context_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_POSTGRES_QUERY_EXECUTOR_HPP
