/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MUTABLE_STORAGE_IMPL_HPP
#define IROHA_MUTABLE_STORAGE_IMPL_HPP

#include <soci/soci.h>

#include "ametsuchi/block_storage.hpp"
#include "ametsuchi/mutable_storage.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class BlockIndex;
    class PeerQuery;
    class PostgresCommandExecutor;
    class PostgresWsvCommand;
    class TransactionExecutor;

    class MutableStorageImpl : public MutableStorage {
      friend class StorageImpl;

     public:
      MutableStorageImpl(
          boost::optional<std::shared_ptr<const iroha::LedgerState>>
              ledger_state,
          std::shared_ptr<PostgresCommandExecutor> command_executor,
          std::unique_ptr<BlockStorage> block_storage,
          logger::LoggerManagerTreePtr log_manager);

      bool apply(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      bool apply(rxcpp::observable<
                     std::shared_ptr<shared_model::interface::Block>> blocks,
                 MutableStoragePredicate predicate) override;

      boost::optional<std::shared_ptr<const iroha::LedgerState>>
      getLedgerState() const;

      expected::Result<CommitResult, std::string> commit(
          BlockStorage &block_storage)
          && override;

      ~MutableStorageImpl() override;

     private:
      std::shared_ptr<soci::session> sql() const {
        return std::shared_ptr<soci::session>(sql_);
      }

     private:
      /**
       * Performs a function inside savepoint, does a rollback if function
       * returned false, and removes the savepoint otherwise. Returns function
       * result
       */
      template <typename Function>
      bool withSavepoint(Function &&function);

      /**
       * Verifies whether the block is applicable using predicate, and applies
       * the block
       */
      bool apply(std::shared_ptr<const shared_model::interface::Block> block,
                 MutableStoragePredicate predicate);

      boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state_;

      std::weak_ptr<soci::session> sql_;
      std::unique_ptr<PostgresWsvCommand> wsv_command_;
      std::unique_ptr<PeerQuery> peer_query_;
      std::unique_ptr<BlockIndex> block_index_;
      std::shared_ptr<TransactionExecutor> transaction_executor_;
      std::unique_ptr<BlockStorage> block_storage_;

      bool committed;

      logger::LoggerPtr log_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MUTABLE_STORAGE_IMPL_HPP
