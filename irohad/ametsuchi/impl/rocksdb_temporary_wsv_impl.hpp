/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_TEMPORARY_WSV_IMPL_HPP
#define IROHA_ROCKSDB_TEMPORARY_WSV_IMPL_HPP

#include "ametsuchi/impl/temporary_wsv_impl.hpp"

namespace shared_model::interface {
  class PermissionToString;
}  // namespace shared_model::interface

namespace iroha::ametsuchi {

  class TransactionExecutor;
  class RocksDbCommandExecutor;
  struct RocksDBContext;

  class RocksDbTemporaryWsvImpl final : public TemporaryWsvImpl {
   public:
    RocksDbTemporaryWsvImpl(
        std::shared_ptr<RocksDbCommandExecutor> command_executor,
        logger::LoggerManagerTreePtr log_manager);

    ~RocksDbTemporaryWsvImpl() = default;

   protected:
    expected::Result<void, validation::CommandError> validateSignatures(
        const shared_model::interface::Transaction &transaction);

    std::shared_ptr<RocksDBContext> tx_context_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_TEMPORARY_WSV_IMPL_HPP
