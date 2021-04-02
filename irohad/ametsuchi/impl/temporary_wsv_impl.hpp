/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TEMPORARY_WSV_IMPL_HPP
#define IROHA_TEMPORARY_WSV_IMPL_HPP

#include <soci/soci.h>

#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/temporary_wsv.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace shared_model {
  namespace interface {
    class PermissionToString;
  }
}  // namespace shared_model

namespace iroha {

  namespace ametsuchi {
    class PostgresCommandExecutor;
    class TransactionExecutor;

    class TemporaryWsvImpl : public TemporaryWsv {
      friend class StorageImpl;

     public:
      struct SavepointWrapperImpl : public TemporaryWsv::SavepointWrapper {
        SavepointWrapperImpl(const TemporaryWsvImpl &wsv,
                             std::string savepoint_name,
                             logger::LoggerPtr log);

        void release() override;

        ~SavepointWrapperImpl() override;

       private:
        std::shared_ptr<soci::session> sql() const;

       private:
        std::weak_ptr<soci::session> sql_;
        std::string savepoint_name_;
        bool is_released_;
        logger::LoggerPtr log_;
      };

      TemporaryWsvImpl(
          std::shared_ptr<PostgresCommandExecutor> &&command_executor,
          logger::LoggerManagerTreePtr log_manager);

      expected::Result<void, validation::CommandError> apply(
          const shared_model::interface::Transaction &transaction) override;

      std::unique_ptr<TemporaryWsv::SavepointWrapper> createSavepoint(
          const std::string &name) override;

      ~TemporaryWsvImpl() override;

     private:
      std::shared_ptr<soci::session> sql() const;

      /**
       * Verifies whether transaction has at least quorum signatures and they
       * are a subset of creator account signatories
       */
      expected::Result<void, validation::CommandError> validateSignatures(
          const shared_model::interface::Transaction &transaction);

      std::weak_ptr<soci::session> sql_;
      std::unique_ptr<TransactionExecutor> transaction_executor_;

      logger::LoggerManagerTreePtr log_manager_;
      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_TEMPORARY_WSV_IMPL_HPP
