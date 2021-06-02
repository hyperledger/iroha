/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_PROCESSOR_HPP
#define IROHA_QUERY_PROCESSOR_HPP

#include <memory>
#include <string>

#include "common/result_fwd.hpp"

namespace shared_model {
  namespace interface {
    class Query;
    class BlocksQuery;
    class QueryResponse;
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
      virtual iroha::expected::Result<
          std::unique_ptr<shared_model::interface::QueryResponse>,
          std::string>
      queryHandle(const shared_model::interface::Query &qry) = 0;

      /**
       * Register client blocks query
       * @param query - client intent
       * @return error if query is invalid
       */
      virtual iroha::expected::Result<void, std::string> blocksQueryHandle(
          shared_model::interface::BlocksQuery const &qry) = 0;

      virtual ~QueryProcessor() = default;
    };
  }  // namespace torii
}  // namespace iroha

#endif  // IROHA_QUERY_PROCESSOR_HPP
