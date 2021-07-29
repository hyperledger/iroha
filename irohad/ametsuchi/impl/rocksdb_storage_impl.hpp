/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_STORAGE_IMPL_HPP
#define IROHA_ROCKSDB_STORAGE_IMPL_HPP

#include "ametsuchi/impl/storage_base.hpp"

namespace shared_model {
  namespace interface {
    class QueryResponseFactory;
  }  // namespace interface
}  // namespace shared_model
namespace iroha {

  class PendingTransactionStorage;

  namespace ametsuchi {

    struct RocksDBPort;
    class AmetsuchiTest;
    class PostgresOptions;
    class VmCaller;
    class RocksDbCommon;
    struct RocksDBContext;

    class RocksDbStorageImpl final : public StorageBase {
     public:
      static expected::Result<std::shared_ptr<RocksDbStorageImpl>, std::string>
      create(
          std::shared_ptr<RocksDBContext> db_context,
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
          logger::LoggerManagerTreePtr log_manager);

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

      iroha::expected::Result<void, std::string> resetPeers() override;

      void freeConnections() override;

      CommitResult commitPrepared(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      std::shared_ptr<WsvQuery> getWsvQuery() const override;

      std::shared_ptr<BlockQuery> getBlockQuery() const override;

      void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) override;

      ~RocksDbStorageImpl() override = default;

     protected:
      RocksDbStorageImpl(
          std::shared_ptr<RocksDBContext> db_context,
          boost::optional<std::shared_ptr<const iroha::LedgerState>>
              ledger_state,
          std::shared_ptr<BlockStorage> block_store,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter,
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              query_response_factory,
          std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
          std::optional<std::reference_wrapper<const VmCaller>> vm_caller,
          std::function<void(
              std::shared_ptr<shared_model::interface::Block const>)> callback,
          logger::LoggerManagerTreePtr log_manager);

     private:
      using StoreBlockResult = iroha::expected::Result<void, std::string>;

      friend class ::iroha::ametsuchi::AmetsuchiTest;
      std::shared_ptr<RocksDBContext> db_context_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_ROCKSDB_STORAGE_IMPL_HPP
