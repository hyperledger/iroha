/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/temporary_wsv_impl.hpp"

#include <boost/format.hpp>
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "cryptography/public_key.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/permission_to_string.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha {
  namespace ametsuchi {
    TemporaryWsvImpl::TemporaryWsvImpl(
        std::unique_ptr<soci::session> sql,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        logger::LoggerManagerTreePtr log_manager)
        : sql_(std::move(sql)),
          command_executor_(std::make_unique<PostgresCommandExecutor>(
              *sql_, std::move(perm_converter))),
          log_manager_(std::move(log_manager)),
          log_(log_manager_->getLogger()) {
      *sql_ << "BEGIN";
    }

    expected::Result<void, validation::CommandError>
    TemporaryWsvImpl::validateSignatures(
        const shared_model::interface::Transaction &transaction) {
      auto keys_range = transaction.signatures()
          | boost::adaptors::transformed(
                            [](const auto &s) { return s.publicKey().hex(); });
      auto keys = std::accumulate(
          std::next(std::begin(keys_range)),
          std::end(keys_range),
          keys_range.front(),
          [](auto acc, const auto &val) { return acc + "'), ('" + val; });
      // not using bool since it is not supported by SOCI
      boost::optional<uint8_t> signatories_valid;

      boost::format query(R"(SELECT sum(count) = :signatures_count
                          AND sum(quorum) <= :signatures_count
                  FROM
                      (SELECT count(public_key)
                      FROM ( VALUES ('%s') ) AS CTE1(public_key)
                      WHERE public_key IN
                          (SELECT public_key
                          FROM account_has_signatory
                          WHERE account_id = :account_id ) ) AS CTE2(count),
                          (SELECT quorum
                          FROM account
                          WHERE account_id = :account_id) AS CTE3(quorum))");

      try {
        auto keys_range_size = boost::size(keys_range);
        *sql_ << (query % keys).str(), soci::into(signatories_valid),
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

    expected::Result<void, validation::CommandError> TemporaryWsvImpl::apply(
        const shared_model::interface::Transaction &transaction) {
      const auto &tx_creator = transaction.creatorAccountId();
      command_executor_->setCreatorAccountId(tx_creator);
      command_executor_->doValidation(true);
      auto execute_command =
          [this](auto &command) -> expected::Result<void, CommandError> {
        // Validate and execute command
        return boost::apply_visitor(*command_executor_, command.get());
      };

      auto savepoint_wrapper = createSavepoint("savepoint_temp_wsv");

      return validateSignatures(transaction) |
                 [savepoint = std::move(savepoint_wrapper),
                  &execute_command,
                  &transaction]()
                 -> expected::Result<void, validation::CommandError> {
        // check transaction's commands validity
        const auto &commands = transaction.commands();
        validation::CommandError cmd_error;
        for (size_t i = 0; i < commands.size(); ++i) {
          // in case of failed command, rollback and return
          auto cmd_is_valid =
              execute_command(commands[i])
                  .match([](const auto &) { return true; },
                         [i, &cmd_error](const auto &error) {
                           cmd_error = {error.error.command_name,
                                        error.error.error_code,
                                        error.error.error_extra,
                                        true,
                                        i};
                           return false;
                         });
          if (not cmd_is_valid) {
            return expected::makeError(cmd_error);
          }
        }
        // success
        savepoint->release();
        return {};
      };
    }

    std::unique_ptr<TemporaryWsv::SavepointWrapper>
    TemporaryWsvImpl::createSavepoint(const std::string &name) {
      return std::make_unique<TemporaryWsvImpl::SavepointWrapperImpl>(
          SavepointWrapperImpl(
              *this,
              name,
              log_manager_->getChild("SavepointWrapper")->getLogger()));
    }

    TemporaryWsvImpl::~TemporaryWsvImpl() {
      try {
        *sql_ << "ROLLBACK";
      } catch (std::exception &e) {
        log_->error("Rollback did not happen: {}", e.what());
      }
    }

    TemporaryWsvImpl::SavepointWrapperImpl::SavepointWrapperImpl(
        const iroha::ametsuchi::TemporaryWsvImpl &wsv,
        std::string savepoint_name,
        logger::LoggerPtr log)
        : sql_{*wsv.sql_},
          savepoint_name_{std::move(savepoint_name)},
          is_released_{false},
          log_(std::move(log)) {
      sql_ << "SAVEPOINT " + savepoint_name_ + ";";
    }

    void TemporaryWsvImpl::SavepointWrapperImpl::release() {
      is_released_ = true;
    }

    TemporaryWsvImpl::SavepointWrapperImpl::~SavepointWrapperImpl() {
      try {
        if (not is_released_) {
          sql_ << "ROLLBACK TO SAVEPOINT " + savepoint_name_ + ";";
        } else {
          sql_ << "RELEASE SAVEPOINT " + savepoint_name_ + ";";
        }
      } catch (std::exception &e) {
        log_->error("SQL error. Reason: {}", e.what());
      }
    }

  }  // namespace ametsuchi
}  // namespace iroha
