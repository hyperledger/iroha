/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEMPORARY_WSV_IMPL_HPP
#define IROHA_TEMPORARY_WSV_IMPL_HPP

#include "ametsuchi/temporary_wsv.hpp"

#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/db_transaction.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace shared_model {
  namespace interface {
    class PermissionToString;
  }
}  // namespace shared_model

namespace iroha::ametsuchi {
  class TransactionExecutor;

  class TemporaryWsvImpl : public TemporaryWsv {
    friend class StorageImpl;

   public:
    struct SavepointWrapperImpl final : public TemporaryWsv::SavepointWrapper {
      SavepointWrapperImpl(DatabaseTransaction &tx,
                           std::string savepoint_name,
                           logger::LoggerPtr log);
      ~SavepointWrapperImpl() override;

      void release() override;

     private:
      DatabaseTransaction &tx_;
      bool is_released_;
      logger::LoggerPtr log_;
      std::string savepoint_name_;
    };

    TemporaryWsvImpl(std::shared_ptr<CommandExecutor> command_executor,
                     logger::LoggerManagerTreePtr log_manager);

    expected::Result<void, validation::CommandError> apply(
        const shared_model::interface::Transaction &transaction) override;

    std::unique_ptr<TemporaryWsv::SavepointWrapper> createSavepoint(
        const std::string &name) override;

    ~TemporaryWsvImpl() override;

    DatabaseTransaction &getDbTransaction() override;

   protected:
    /**
     * Verifies whether transaction has at least quorum signatures and they
     * are a subset of creator account signatories
     */
    virtual expected::Result<void, validation::CommandError> validateSignatures(
        const shared_model::interface::Transaction &transaction) = 0;

    DatabaseTransaction &tx_;
    std::unique_ptr<TransactionExecutor> transaction_executor_;
    logger::LoggerManagerTreePtr log_manager_;
    logger::LoggerPtr log_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_TEMPORARY_WSV_IMPL_HPP
