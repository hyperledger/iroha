/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_STORAGE_IMPL_HPP
#define IROHA_STORAGE_IMPL_HPP

#include "ametsuchi/storage.hpp"

#include <atomic>
#include <shared_mutex>

#include <soci/soci.h>
#include <boost/optional.hpp>
#include "ametsuchi/block_storage_factory.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/key_value_storage.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/reconnection_strategy.hpp"
#include "common/result.hpp"
#include "interfaces/permission_to_string.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class StorageImpl : public Storage {
     public:
      static expected::Result<std::shared_ptr<StorageImpl>, std::string> create(
          std::unique_ptr<ametsuchi::PostgresOptions> postgres_options,
          std::shared_ptr<PoolWrapper> pool_wrapper,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter,
          std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
          std::unique_ptr<BlockStorage> persistent_block_storage,
          logger::LoggerManagerTreePtr log_manager,
          size_t pool_size = 10);

      expected::Result<std::unique_ptr<TemporaryWsv>, std::string>
      createTemporaryWsv() override;

      expected::Result<std::unique_ptr<MutableStorage>, std::string>
      createMutableStorage() override;

      boost::optional<std::shared_ptr<PeerQuery>> createPeerQuery()
          const override;

      boost::optional<std::shared_ptr<BlockQuery>> createBlockQuery()
          const override;

      boost::optional<std::shared_ptr<QueryExecutor>> createQueryExecutor(
          std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
          std::shared_ptr<shared_model::interface::QueryResponseFactory>
              response_factory) const override;

      bool insertBlock(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      expected::Result<void, std::string> insertPeer(
          const shared_model::interface::Peer &peer) override;

      expected::Result<std::unique_ptr<MutableStorage>, std::string>
      createMutableStorage(BlockStorageFactory &storage_factory) override;

      void reset() override;

      expected::Result<void, std::string> resetWsv() override;

      void resetPeers() override;

      void dropStorage() override;

      void freeConnections() override;

      CommitResult commit(
          std::unique_ptr<MutableStorage> mutable_storage) override;

      bool preparedCommitEnabled() const override;

      CommitResult commitPrepared(
          std::shared_ptr<const shared_model::interface::Block> block) override;

      std::shared_ptr<WsvQuery> getWsvQuery() const override;

      std::shared_ptr<BlockQuery> getBlockQuery() const override;

      rxcpp::observable<std::shared_ptr<const shared_model::interface::Block>>
      on_commit() override;

      void prepareBlock(std::unique_ptr<TemporaryWsv> wsv) override;

      ~StorageImpl() override;

     protected:
      StorageImpl(
          boost::optional<std::shared_ptr<const iroha::LedgerState>>
              ledger_state,
          std::unique_ptr<ametsuchi::PostgresOptions> postgres_options,
          std::unique_ptr<BlockStorage> block_store,
          std::shared_ptr<PoolWrapper> pool_wrapper,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter,
          std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
          size_t pool_size,
          logger::LoggerManagerTreePtr log_manager);

      // db info
      const std::unique_ptr<ametsuchi::PostgresOptions> postgres_options_;

     private:
      using StoreBlockResult = iroha::expected::Result<void, std::string>;

      /**
       * revert prepared transaction
       */

      /**
       * add block to block storage
       */
      StoreBlockResult storeBlock(
          std::shared_ptr<const shared_model::interface::Block> block);

      /**
       * Method tries to perform rollback on passed session
       */
      void tryRollback(soci::session &session);

      std::unique_ptr<BlockStorage> block_store_;

      std::shared_ptr<PoolWrapper> pool_wrapper_;

      /// ref for pool_wrapper_::connection_pool_
      std::shared_ptr<soci::connection_pool> &connection_;

      rxcpp::composite_subscription notifier_lifetime_;
      rxcpp::subjects::subject<
          std::shared_ptr<const shared_model::interface::Block>>
          notifier_;

      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;

      std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory_;

      logger::LoggerManagerTreePtr log_manager_;
      logger::LoggerPtr log_;

      mutable std::shared_timed_mutex drop_mutex_;

      const size_t pool_size_;

      bool prepared_blocks_enabled_;

      std::atomic<bool> block_is_prepared_;

      std::string prepared_block_name_;

      boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_STORAGE_IMPL_HPP
