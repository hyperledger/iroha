/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_storage_impl.hpp"

#include <utility>

#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/mutable_storage_impl.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/rocksdb_block_query.hpp"
#include "ametsuchi/impl/rocksdb_command_executor.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/impl/rocksdb_indexer.hpp"
#include "ametsuchi/impl/rocksdb_query_executor.hpp"
#include "ametsuchi/impl/rocksdb_settings_query.hpp"
#include "ametsuchi/impl/rocksdb_specific_query_executor.hpp"
#include "ametsuchi/impl/rocksdb_temporary_wsv_impl.hpp"
#include "ametsuchi/impl/rocksdb_wsv_command.hpp"
#include "ametsuchi/impl/rocksdb_wsv_query.hpp"
#include "ametsuchi/impl/temporary_wsv_impl.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace iroha::ametsuchi {

  RocksDbStorageImpl::RocksDbStorageImpl(
      std::shared_ptr<RocksDBContext> db_context,
      boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state,
      std::shared_ptr<BlockStorage> block_store,
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter,
      std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory,
      std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
      std::optional<std::reference_wrapper<const VmCaller>> vm_caller,
      std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
          callback,
      logger::LoggerManagerTreePtr log_manager)
      : StorageBase(std::move(ledger_state),
                    std::move(block_store),
                    std::move(perm_converter),
                    std::move(pending_txs_storage),
                    std::move(query_response_factory),
                    std::move(temporary_block_storage_factory),
                    std::move(vm_caller),
                    std::move(log_manager),
                    "prepared_block_",
                    std::move(callback),
                    false),
        db_context_(std::move(db_context)) {}

  std::unique_ptr<TemporaryWsv> RocksDbStorageImpl::createTemporaryWsv(
      std::shared_ptr<CommandExecutor> command_executor) {
    auto rdb_command_executor =
        std::dynamic_pointer_cast<RocksDbCommandExecutor>(command_executor);
    if (rdb_command_executor == nullptr) {
      throw std::runtime_error("Bad CommandExecutor cast!");
    }
    // if we create temporary storage, then we intend to validate a new
    // proposal. this means that any state prepared before that moment is
    // not needed and must be removed to prevent locking
    command_executor->skipChanges();
    return std::make_unique<RocksDbTemporaryWsvImpl>(
        std::move(rdb_command_executor),
        logManager()->getChild("TemporaryWorldStateView"));
  }

  expected::Result<std::unique_ptr<QueryExecutor>, std::string>
  RocksDbStorageImpl::createQueryExecutor(
      std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          response_factory) const {
    auto log_manager = logManager()->getChild("QueryExecutor");
    return std::make_unique<RocksDbQueryExecutor>(
        response_factory,
        std::make_shared<RocksDbSpecificQueryExecutor>(
            db_context_,
            *blockStore(),
            std::move(pending_txs_storage),
            response_factory,
            permConverter()),
        log_manager->getLogger());
  }

  expected::Result<void, std::string> RocksDbStorageImpl::insertPeer(
      const shared_model::interface::Peer &peer) {
    log()->info("Insert peer {}", peer.pubkey());
    RocksDBWsvCommand wsv_command(db_context_);
    return wsv_command.insertPeer(peer);
  }

  expected::Result<std::unique_ptr<CommandExecutor>, std::string>
  RocksDbStorageImpl::createCommandExecutor() {
    return std::make_unique<RocksDbCommandExecutor>(
        db_context_,
        permConverter(),
        std::make_shared<RocksDbSpecificQueryExecutor>(db_context_,
                                                       *blockStore(),
                                                       pendingTxStorage(),
                                                       queryResponseFactory(),
                                                       permConverter()),
        vmCaller());
  }

  expected::Result<std::unique_ptr<MutableStorage>, std::string>
  RocksDbStorageImpl::createMutableStorage(
      std::shared_ptr<CommandExecutor> command_executor) {
    return createMutableStorage(std::move(command_executor),
                                *temporaryBlockStorageFactory());
  }

  expected::Result<std::unique_ptr<MutableStorage>, std::string>
  RocksDbStorageImpl::createMutableStorage(
      std::shared_ptr<CommandExecutor> command_executor,
      BlockStorageFactory &storage_factory) {
    // if we create mutable storage, then we intend to mutate wsv
    // this means that any state prepared before that moment is not needed
    // and must be removed to prevent locking
    command_executor->skipChanges();

    auto ms_log_manager = logManager()->getChild("RocksDbMutableStorageImpl");
    auto wsv_command = std::make_unique<RocksDBWsvCommand>(db_context_);
    auto peer_query =
        std::make_unique<PeerQueryWsv>(std::make_shared<RocksDBWsvQuery>(
            db_context_, ms_log_manager->getChild("WsvQuery")->getLogger()));
    auto block_index = std::make_unique<BlockIndexImpl>(
        std::make_unique<RocksDBIndexer>(db_context_),
        ms_log_manager->getChild("BlockIndexImpl")->getLogger());

    return std::make_unique<MutableStorageImpl>(
        ledgerState(),
        std::move(wsv_command),
        std::move(peer_query),
        std::move(block_index),
        std::move(command_executor),
        storage_factory.create().assumeValue(),
        std::move(ms_log_manager));
  }

  iroha::expected::Result<void, std::string> RocksDbStorageImpl::resetPeers() {
    log()->info("Remove everything from peers table. [UNUSED]");
    return {};
  }

  void RocksDbStorageImpl::freeConnections() {
    log()->info("Free connections. [UNUSED]");
  }

  expected::Result<std::shared_ptr<RocksDbStorageImpl>, std::string>
  RocksDbStorageImpl::create(
      std::shared_ptr<RocksDBContext> db_context,
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter,
      std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory,
      std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
      std::shared_ptr<BlockStorage> persistent_block_storage,
      std::optional<std::reference_wrapper<const VmCaller>> vm_caller_ref,
      std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
          callback,
      logger::LoggerManagerTreePtr log_manager) {
    boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state;
    {
      RocksDBWsvQuery wsv_query(db_context,
                                log_manager->getChild("WsvQuery")->getLogger());

      auto maybe_top_block_info = wsv_query.getTopBlockInfo();
      auto maybe_ledger_peers = wsv_query.getPeers(false);
      auto maybe_ledger_sync_peers = wsv_query.getPeers(true);

      if (expected::hasValue(maybe_top_block_info) && maybe_ledger_peers
          && maybe_ledger_sync_peers)
        ledger_state = std::make_shared<const iroha::LedgerState>(
            std::move(*maybe_ledger_peers),
            std::move(*maybe_ledger_sync_peers),
            maybe_top_block_info.assumeValue().height,
            maybe_top_block_info.assumeValue().top_hash);
    }

    return expected::makeValue(std::shared_ptr<RocksDbStorageImpl>(
        new RocksDbStorageImpl(std::move(db_context),
                               std::move(ledger_state),
                               std::move(persistent_block_storage),
                               perm_converter,
                               std::move(pending_txs_storage),
                               std::move(query_response_factory),
                               std::move(temporary_block_storage_factory),
                               std::move(vm_caller_ref),
                               std::move(callback),
                               std::move(log_manager))));
  }

  CommitResult RocksDbStorageImpl::commitPrepared(
      std::shared_ptr<const shared_model::interface::Block> block) {
    RocksDbTransaction tx_context(db_context_);

    RocksDBWsvCommand wsv_command(db_context_);
    RocksDBWsvQuery wsv_query(
        db_context_, this->logManager()->getChild("WsvQuery")->getLogger());
    auto indexer = std::make_unique<RocksDBIndexer>(db_context_);

    return StorageBase::commitPreparedImpl(
        block, tx_context, wsv_command, wsv_query, std::move(indexer));
  }

  std::shared_ptr<WsvQuery> RocksDbStorageImpl::getWsvQuery() const {
    return std::make_shared<RocksDBWsvQuery>(
        db_context_, logManager()->getChild("WsvQuery")->getLogger());
  }

  std::shared_ptr<BlockQuery> RocksDbStorageImpl::getBlockQuery() const {
    return std::make_shared<RocksDbBlockQuery>(
        db_context_,
        *blockStore(),
        logManager()->getChild("RocksDbBlockQuery")->getLogger());
  }

  boost::optional<std::unique_ptr<SettingQuery>>
  RocksDbStorageImpl::createSettingQuery() const {
    std::unique_ptr<SettingQuery> setting_query_ptr =
        std::make_unique<RocksDbSettingQuery>(
            db_context_,
            logManager()->getChild("RocksDbSettingQuery")->getLogger());
    return boost::make_optional(std::move(setting_query_ptr));
  }

  void RocksDbStorageImpl::prepareBlock(std::unique_ptr<TemporaryWsv> wsv) {
    RocksDbTransaction db_context(db_context_);
    StorageBase::prepareBlockImpl(std::move(wsv), db_context);
  }

}  // namespace iroha::ametsuchi
