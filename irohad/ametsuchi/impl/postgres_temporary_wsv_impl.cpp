/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_temporary_wsv_impl.hpp"

#include <boost/algorithm/string/join.hpp>
#include <boost/format.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_db_transaction.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/permission_to_string.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha::ametsuchi {

  PostgresTemporaryWsvImpl::PostgresTemporaryWsvImpl(
      std::shared_ptr<PostgresCommandExecutor> command_executor,
      logger::LoggerManagerTreePtr log_manager)
      : TemporaryWsvImpl(command_executor, log_manager),
        sql_(command_executor->getSession()) {}

  expected::Result<void, validation::CommandError>
  PostgresTemporaryWsvImpl::validateSignatures(
      const shared_model::interface::Transaction &transaction) {
    auto keys_range = transaction.signatures()
        | boost::adaptors::transformed(
                          [](const auto &s) { return s.publicKey(); });
    auto keys = boost::algorithm::join(keys_range, "'), ('");
    // not using bool since it is not supported by SOCI
    boost::optional<uint8_t> signatories_valid;

    boost::format query(R"(SELECT sum(count) = :signatures_count
                          AND sum(quorum) <= :signatures_count
                  FROM
                      (SELECT count(public_key)
                      FROM ( VALUES ('%s') ) AS CTE1(public_key)
                      WHERE lower(public_key) IN
                          (SELECT public_key
                          FROM account_has_signatory
                          WHERE account_id = :account_id ) ) AS CTE2(count),
                          (SELECT quorum
                          FROM account
                          WHERE account_id = :account_id) AS CTE3(quorum))");

    try {
      auto keys_range_size = boost::size(keys_range);
      sql_ << (query % keys).str(), soci::into(signatories_valid),
          soci::use(keys_range_size, "signatures_count"),
          soci::use(transaction.creatorAccountId(), "account_id");
    } catch (const std::exception &e) {
      auto error_str = "Transaction " + transaction.toString()
          + " failed signatures validation with db error: " + e.what();
      // TODO [IR-1816] Akvinikym 29.10.18: substitute error code magic number
      // with named constant
      return expected::makeError(validation::CommandError{
          "signatures validation", 1, error_str, false});
    }

    if (signatories_valid and *signatories_valid) {
      return {};
    } else {
      auto error_str = "Transaction " + transaction.toString()
          + " failed signatures validation";
      // TODO [IR-1816] Akvinikym 29.10.18: substitute error code magic number
      // with named constant
      return expected::makeError(validation::CommandError{
          "signatures validation", 2, error_str, false});
    }
  }

}  // namespace iroha::ametsuchi
