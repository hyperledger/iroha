/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_query_executor.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/size.hpp>
#include "ametsuchi/specific_query_executor.hpp"
#include "interfaces/iroha_internal/query_response_factory.hpp"
#include "interfaces/queries/blocks_query.hpp"
#include "interfaces/queries/query.hpp"
#include "logger/logger.hpp"

using namespace shared_model::interface::permissions;

namespace iroha::ametsuchi {

  PostgresQueryExecutor::PostgresQueryExecutor(
      std::unique_ptr<soci::session> sql,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          response_factory,
      std::shared_ptr<SpecificQueryExecutor> specific_query_executor,
      logger::LoggerPtr log)
      : QueryExecutorBase(std::move(response_factory),
                          std::move(specific_query_executor),
                          std::move(log)),
        sql_(std::move(sql)) {}

  bool PostgresQueryExecutor::validateSignatures(
      const shared_model::interface::Query &query) {
    return validateSignaturesImpl(query);
  }

  bool PostgresQueryExecutor::validateSignatures(
      const shared_model::interface::BlocksQuery &query) {
    return validateSignaturesImpl(query);
  }

  template <class Q>
  bool PostgresQueryExecutor::validateSignaturesImpl(const Q &query) {
    auto keys_range =
        query.signatures() | boost::adaptors::transformed([](const auto &s) {
          return s.publicKey();
        });

    if (boost::size(keys_range) != 1) {
      return false;
    }
    std::string keys = *std::begin(keys_range);
    // not using bool since it is not supported by SOCI
    boost::optional<uint8_t> signatories_valid;

    auto qry = R"(
        SELECT count(public_key) = 1
        FROM account_has_signatory
        WHERE account_id = :account_id AND public_key = lower(:pk)
        )";

    try {
      *sql_ << qry, soci::into(signatories_valid),
          soci::use(query.creatorAccountId(), "account_id"),
          soci::use(keys, "pk");
    } catch (const std::exception &e) {
      log_->error("{}", e.what());
      return false;
    }

    return signatories_valid and *signatories_valid;
  }

}  // namespace iroha::ametsuchi
