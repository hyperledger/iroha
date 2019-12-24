/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_EXECUTOR_FACTORY_HPP
#define IROHA_QUERY_EXECUTOR_FACTORY_HPP

#include <boost/optional.hpp>

#include "ametsuchi/query_executor.hpp"
#include "common/result_fwd.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "pending_txs_storage/pending_txs_storage.hpp"

namespace iroha {
  namespace ametsuchi {
    class QueryExecutorFactory {
     public:
      /**
       * Creates a query executor from the current state
       */
      virtual iroha::expected::Result<std::unique_ptr<QueryExecutor>,
                                      std::string>
      createQueryExecutor(
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              response_factory) const = 0;

      virtual ~QueryExecutorFactory() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_QUERY_EXECUTOR_FACTORY_HPP
