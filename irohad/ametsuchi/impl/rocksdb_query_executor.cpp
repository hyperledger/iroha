/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_query_executor.hpp"

#include "ametsuchi/impl/rocksdb_specific_query_executor.hpp"
#include "common/to_lower.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/query.hpp"
#include "logger/logger.hpp"

using namespace shared_model::interface::permissions;

namespace iroha::ametsuchi {

  RocksDbQueryExecutor::RocksDbQueryExecutor(
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          response_factory,
      std::shared_ptr<RocksDbSpecificQueryExecutor> specific_query_executor,
      logger::LoggerPtr log)
      : QueryExecutorBase(std::move(response_factory),
                          specific_query_executor,
                          std::move(log)),
        tx_context_(specific_query_executor->getTxContext()) {}

  bool RocksDbQueryExecutor::validateSignatures(
      const shared_model::interface::Query &query) {
    return validateSignaturesImpl(query);
  }

  bool RocksDbQueryExecutor::validateSignatures(
      const shared_model::interface::BlocksQuery &query) {
    return validateSignaturesImpl(query);
  }

  template <class Q>
  bool RocksDbQueryExecutor::validateSignaturesImpl(const Q &query) {
    auto const &[account, domain] = staticSplitId<2>(query.creatorAccountId());
    RocksDbCommon common(tx_context_);

    std::string pk;
    for (auto &signatory : query.signatures()) {
      pk.clear();
      toLowerAppend(signatory.publicKey(), pk);
      if (auto result =
              forSignatory<kDbOperation::kCheck, kDbEntry::kMustExist>(
                  common, account, domain, pk);
          expected::hasError(result)) {
        log_->error("code:{}, description:{}",
                    result.assumeError().code,
                    result.assumeError().description);
        return false;
      }
    }

    return true;
  }

}  // namespace iroha::ametsuchi
