/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STORAGE_IMPL_HPP
#define IROHA_STORAGE_IMPL_HPP

#include "ametsuchi/impl/storage_base.hpp"

#include <soci/soci.h>

namespace shared_model {
  namespace interface {
    class QueryResponseFactory;
  }  // namespace interface
}  // namespace shared_model
namespace iroha {

  class PendingTransactionStorage;

  namespace ametsuchi {

    class AmetsuchiTest;
    class PostgresOptions;
    class VmCaller;

    class StorageImpl final : public StorageBase {
     public:
      static expected::Result<std::shared_ptr<StorageImpl>, std::string> create(
          const PostgresOptions &postgres_options,
          std::shared_ptr<PoolWrapper> pool_wrapper,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter,
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              query_response_factory,
          std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
          std::shared_ptr<BlockStorage> persistent_block_storage,
          std::optional<std::reference_wrapper<const VmCaller>> vm_caller_ref,
          std::function<void(
              std::shared_ptr<shared_model::interface::Block const>)> callback,
          logger::LoggerManagerTreePtr log_manager,
          size_t pool_size = 10);

      expected::Result<std::unique_ptr<CommandExecutor>, std::string>
      createCommandExecutor() override;

      std::unique_ptr<TemporaryWsv> createTemporaryWsv(
          std::shared_ptr<CommandExecutor> command_executor) override;

      boost::optional<std::unique_ptr<SettingQuery>> createSettingQuery()
          const override;

      iroha::expected::Result<std::unique_ptr<QueryExecutor>, std::string>
      createQueryExecutor(
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              response_factory) const override;

      expected::Result<void, std::string> insertPeer(
          const shared_model::interface::Peer &peer) override;

      iroha::expected::Result<std::unique_ptr<MutableStorage>, std::string>
      createMutableStorage(std::shared_ptr<CommandExecutor> command_executor,
                           BlockStorageFactory &storage_factory) override;

      expected::Result<std::unique_ptr<MutableStorage>, std::string>
      createMutableStorage(
          std::shared_ptr<CommandExecutor> command_executor) override;

      expected::Result<void, std::string> resetPeers() override;

      void freeConnections() override;

      CommitResult commitPrepared(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      std::shared_ptr<WsvQuery> getWsvQuery() const override;

      std::shared_ptr<BlockQuery> getBlockQuery() const override;

      void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) override;

      ~StorageImpl() override;

     protected:
      StorageImpl(
          boost::optional<std::shared_ptr<const iroha::LedgerState>>
              ledger_state,
          const PostgresOptions &postgres_options,
          std::shared_ptr<BlockStorage> block_store,
          std::shared_ptr<PoolWrapper> pool_wrapper,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter,
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              query_response_factory,
          std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
          size_t pool_size,
          std::optional<std::reference_wrapper<const VmCaller>> vm_caller,
          std::function<void(
              std::shared_ptr<shared_model::interface::Block const>)> callback,
          logger::LoggerManagerTreePtr log_manager);

     private:
      friend class ::iroha::ametsuchi::AmetsuchiTest;

      /**
       * Method tries to perform rollback on passed session
       */
      void tryRollback(soci::session &session);

      /// ref for pool_wrapper_::connection_pool_
      std::shared_ptr<PoolWrapper> pool_wrapper_;
      std::shared_ptr<soci::connection_pool> &connection_;
      mutable std::shared_timed_mutex drop_mutex_;
      const size_t pool_size_;
      std::string prepared_block_name_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_STORAGE_IMPL_HPP
