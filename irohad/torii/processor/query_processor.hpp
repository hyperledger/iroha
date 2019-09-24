/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_PROCESSOR_HPP
#define IROHA_QUERY_PROCESSOR_HPP

#include <rxcpp/rx-lite.hpp>

#include <memory>

namespace shared_model {
  namespace interface {
    class Query;
    class BlocksQuery;
    class QueryResponse;
    class BlockQueryResponse;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace torii {

    /**
     * QueryProcessor provides start point for queries in the whole system
     */
    class QueryProcessor {
     public:
      /**
       * Perform client query
       * @param qry - client intent
       * @return resulted response
       */
      virtual std::unique_ptr<shared_model::interface::QueryResponse>
      queryHandle(const shared_model::interface::Query &qry) = 0;
      /**
       * Register client blocks query
       * @param query - client intent
       * @return observable with block query responses
       */
      virtual rxcpp::observable<
          std::shared_ptr<shared_model::interface::BlockQueryResponse>>
      blocksQueryHandle(const shared_model::interface::BlocksQuery &qry) = 0;

      virtual ~QueryProcessor(){};
    };
  }  // namespace torii
}  // namespace iroha

#endif  // IROHA_QUERY_PROCESSOR_HPP
