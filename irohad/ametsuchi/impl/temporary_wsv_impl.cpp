/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/temporary_wsv_impl.hpp"

#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/permission_to_string.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha::ametsuchi {
  TemporaryWsvImpl::TemporaryWsvImpl(
      std::shared_ptr<CommandExecutor> command_executor,
      logger::LoggerManagerTreePtr log_manager)
      : tx_(command_executor->dbSession()),
        transaction_executor_(
            std::make_unique<TransactionExecutor>(std::move(command_executor))),
        log_manager_(std::move(log_manager)),
        log_(log_manager_->getLogger()) {
    tx_.begin();
  }

  expected::Result<void, validation::CommandError> TemporaryWsvImpl::apply(
      const shared_model::interface::Transaction &transaction) {
    auto savepoint_wrapper = createSavepoint("savepoint_temp_wsv");
    return validateSignatures(transaction) |
               [this, savepoint = std::move(savepoint_wrapper), &transaction]()
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
            tx_,
            name,
            log_manager_->getChild("SavepointWrapper")->getLogger()));
  }

  TemporaryWsvImpl::~TemporaryWsvImpl() {
    try {
      tx_.rollback();
    } catch (std::exception &e) {
      log_->error("Rollback did not happen: {}", e.what());
    }
  }

  DatabaseTransaction &TemporaryWsvImpl::getDbTransaction() {
    return tx_;
  }

  TemporaryWsvImpl::SavepointWrapperImpl::SavepointWrapperImpl(
      DatabaseTransaction &tx,
      std::string savepoint_name,
      logger::LoggerPtr log)
      : tx_(tx),
        is_released_{false},
        log_(std::move(log)),
        savepoint_name_(std::move(savepoint_name)) {
    tx_.savepoint(savepoint_name_);
  }

  void TemporaryWsvImpl::SavepointWrapperImpl::release() {
    is_released_ = true;
  }

  TemporaryWsvImpl::SavepointWrapperImpl::~SavepointWrapperImpl() {
    try {
      if (not is_released_) {
        tx_.rollbackToSavepoint(savepoint_name_);
      } else {
        tx_.releaseSavepoint(savepoint_name_);
      }
    } catch (std::exception &e) {
      log_->error("SQL error. Reason: {}", e.what());
    }
  }

}  // namespace iroha::ametsuchi
