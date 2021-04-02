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

namespace iroha {
  namespace ametsuchi {

    PostgresQueryExecutor::PostgresQueryExecutor(
        std::shared_ptr<soci::session> const &sql,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory,
        std::shared_ptr<SpecificQueryExecutor> specific_query_executor,
        logger::LoggerPtr log)
        : sql_(sql),
          specific_query_executor_(std::move(specific_query_executor)),
          query_response_factory_{std::move(response_factory)},
          log_(std::move(log)) {}

    template <class Q>
    bool PostgresQueryExecutor::validateSignatures(const Q &query) {
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

    QueryExecutorResult PostgresQueryExecutor::validateAndExecute(
        const shared_model::interface::Query &query,
        const bool validate_signatories = true) {
      if (validate_signatories and not validateSignatures(query)) {
        // TODO [IR-1816] Akvinikym 03.12.18: replace magic number 3
        // with a named constant
        return query_response_factory_->createErrorQueryResponse(
            shared_model::interface::QueryResponseFactory::ErrorQueryType::
                kStatefulFailed,
            "query signatories did not pass validation",
            3,
            query.hash());
      }
      return specific_query_executor_->execute(query);
    }

    bool PostgresQueryExecutor::validate(
        const shared_model::interface::BlocksQuery &query,
        const bool validate_signatories = true) {
      if (validate_signatories and not validateSignatures(query)) {
        log_->error("query signatories did not pass validation");
        return false;
      }
      if (not specific_query_executor_->hasAccountRolePermission(
              Role::kGetBlocks, query.creatorAccountId())) {
        log_->error("query creator does not have enough permissions");
        return false;
      }

      return true;
    }

  }  // namespace ametsuchi
}  // namespace iroha
