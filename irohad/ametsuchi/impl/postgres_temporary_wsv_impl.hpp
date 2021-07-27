/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_TEMPORARY_WSV_IMPL_HPP
#define IROHA_POSTGRES_TEMPORARY_WSV_IMPL_HPP

#include "ametsuchi/impl/temporary_wsv_impl.hpp"

#include <soci/soci.h>

namespace shared_model {
  namespace interface {
    class PermissionToString;
  }
}  // namespace shared_model

namespace iroha::ametsuchi {

  class PostgresCommandExecutor;
  class TransactionExecutor;

  class PostgresTemporaryWsvImpl final : public TemporaryWsvImpl {
   public:
    PostgresTemporaryWsvImpl(
        std::shared_ptr<PostgresCommandExecutor> command_executor,
        logger::LoggerManagerTreePtr log_manager);

    ~PostgresTemporaryWsvImpl() = default;

    soci::session &getSession() {
      return sql_;
    }

   protected:
    expected::Result<void, validation::CommandError> validateSignatures(
        const shared_model::interface::Transaction &transaction);

    soci::session &sql_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_TEMPORARY_WSV_IMPL_HPP
