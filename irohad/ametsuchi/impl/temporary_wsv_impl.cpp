/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/temporary_wsv_impl.hpp"

#include <boost/algorithm/string/join.hpp>
#include <boost/format.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/permission_to_string.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha {
  namespace ametsuchi {
    TemporaryWsvImpl::TemporaryWsvImpl(
        std::shared_ptr<PostgresCommandExecutor> &&command_executor,
        logger::LoggerManagerTreePtr log_manager)
        : sql_(command_executor->getSession()),
          transaction_executor_(std::make_unique<TransactionExecutor>(
              std::move(command_executor))),
          log_manager_(std::move(log_manager)),
          log_(log_manager_->getLogger()) {
      *sql() << "BEGIN";
    }

    std::shared_ptr<soci::session> TemporaryWsvImpl::sql() const {
      return std::shared_ptr<soci::session>(sql_);
    }

    expected::Result<void, validation::CommandError>
    TemporaryWsvImpl::validateSignatures(
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
        *sql() << (query % keys).str(), soci::into(signatories_valid),
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
      auto savepoint_wrapper = createSavepoint("savepoint_temp_wsv");

      return validateSignatures(transaction) |
                 [this,
                  savepoint = std::move(savepoint_wrapper),
                  &transaction]()
                 -> expected::Result<void, validation::CommandError> {
        if (auto error = expected::resultToOptionalError(
                transaction_executor_->execute(transaction, true))) {
          return expected::makeError(
              validation::CommandError{error->command_error.command_name,
                                       error->command_error.error_code,
                                       error->command_error.error_extra,
                                       true,
                                       error->command_index});
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
        *sql() << "ROLLBACK";
      } catch (std::exception &e) {
        log_->error("Rollback did not happen: {}", e.what());
      }
    }

    TemporaryWsvImpl::SavepointWrapperImpl::SavepointWrapperImpl(
        const iroha::ametsuchi::TemporaryWsvImpl &wsv,
        std::string savepoint_name,
        logger::LoggerPtr log)
        : sql_{wsv.sql_},
          savepoint_name_{std::move(savepoint_name)},
          is_released_{false},
          log_(std::move(log)) {
      *sql() << "SAVEPOINT " + savepoint_name_ + ";";
    }

    void TemporaryWsvImpl::SavepointWrapperImpl::release() {
      is_released_ = true;
    }

    std::shared_ptr<soci::session> TemporaryWsvImpl::SavepointWrapperImpl::sql()
        const {
      return std::shared_ptr<soci::session>{sql_};
    }

    TemporaryWsvImpl::SavepointWrapperImpl::~SavepointWrapperImpl() {
      try {
        if (not is_released_) {
          *sql() << "ROLLBACK TO SAVEPOINT " + savepoint_name_ + ";";
        } else {
          *sql() << "RELEASE SAVEPOINT " + savepoint_name_ + ";";
        }
      } catch (std::exception &e) {
        log_->error("SQL error. Reason: {}", e.what());
      }
    }

  }  // namespace ametsuchi
}  // namespace iroha
