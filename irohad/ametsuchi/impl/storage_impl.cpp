/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_impl.hpp"

#include <soci/callbacks.h>
#include <soci/postgresql/soci-postgresql.h>

#include "ametsuchi/impl/block_index_impl.hpp"
#include "ametsuchi/impl/mutable_storage_impl.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_block_query.hpp"
#include "ametsuchi/impl/postgres_block_storage_factory.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_setting_query.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "ametsuchi/impl/postgres_temporary_wsv_impl.hpp"
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "backend/protobuf/permissions.hpp"
#include "common/byteutils.hpp"
#include "common/result.hpp"
#include "common/result_try.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"

namespace iroha::ametsuchi {

  StorageImpl::StorageImpl(
      boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state,
      const ametsuchi::PostgresOptions &postgres_options,
      std::shared_ptr<BlockStorage> block_store,
      std::shared_ptr<PoolWrapper> pool_wrapper,
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter,
      std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          query_response_factory,
      std::unique_ptr<BlockStorageFactory> temporary_block_storage_factory,
      size_t pool_size,
      std::optional<std::reference_wrapper<const VmCaller>> vm_caller_ref,
      std::function<void(std::shared_ptr<shared_model::interface::Block const>)>
          callback,
      logger::LoggerManagerTreePtr log_manager)
      : StorageBase(std::move(ledger_state),
                    std::move(block_store),
                    std::move(perm_converter),
                    std::move(pending_txs_storage),
                    std::move(query_response_factory),
                    std::move(temporary_block_storage_factory),
                    std::move(vm_caller_ref),
                    std::move(log_manager),
                    postgres_options.preparedBlockName(),
                    std::move(callback),
                    pool_wrapper->enable_prepared_transactions_),
        pool_wrapper_(pool_wrapper),
        connection_(pool_wrapper->connection_pool_),
        pool_size_(pool_size),
        prepared_block_name_(postgres_options.preparedBlockName()) {}

  std::unique_ptr<TemporaryWsv> StorageImpl::createTemporaryWsv(
      std::shared_ptr<CommandExecutor> command_executor) {
    auto postgres_command_executor =
        std::dynamic_pointer_cast<PostgresCommandExecutor>(command_executor);
    if (postgres_command_executor == nullptr) {
      throw std::runtime_error("Bad PostgresCommandExecutor cast!");
    }
    // if we create temporary storage, then we intend to validate a new
    // proposal. this means that any state prepared before that moment is
    // not needed and must be removed to prevent locking
    tryRollback(postgres_command_executor->getSession());
    return std::make_unique<PostgresTemporaryWsvImpl>(
        std::move(postgres_command_executor),
        logManager()->getChild("TemporaryWorldStateView"));
  }

  iroha::expected::Result<std::unique_ptr<QueryExecutor>, std::string>
  StorageImpl::createQueryExecutor(
      std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
      std::shared_ptr<shared_model::interface::QueryResponseFactory>
          response_factory) const {
    std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
    if (not connection_) {
      return "createQueryExecutor: connection to database is not initialised";
    }
    auto sql = std::make_unique<soci::session>(*connection_);
    auto log_manager = logManager()->getChild("QueryExecutor");
    return std::make_unique<PostgresQueryExecutor>(
        std::move(sql),
        response_factory,
        std::make_shared<PostgresSpecificQueryExecutor>(
            *sql,
            *blockStore(),
            std::move(pending_txs_storage),
            response_factory,
            permConverter(),
            log_manager->getChild("SpecificQueryExecutor")->getLogger()),
        log_manager->getLogger());
  }

  expected::Result<void, std::string> StorageImpl::insertPeer(
      const shared_model::interface::Peer &peer) {
    log()->info("Insert peer {}", peer.pubkey());
    soci::session sql(*connection_);
    PostgresWsvCommand wsv_command(sql);
    return wsv_command.insertPeer(peer);
  }

  expected::Result<std::unique_ptr<CommandExecutor>, std::string>
  StorageImpl::createCommandExecutor() {
    std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
    if (connection_ == nullptr) {
      return expected::makeError("Connection was closed");
    }
    auto sql = std::make_unique<soci::session>(*connection_);
    return std::make_unique<PostgresCommandExecutor>(
        std::move(sql),
        permConverter(),
        std::make_shared<PostgresSpecificQueryExecutor>(
            *sql,
            *blockStore(),
            pendingTxStorage(),
            queryResponseFactory(),
            permConverter(),
            logManager()->getChild("SpecificQueryExecutor")->getLogger()),
        vmCaller());
  }

  expected::Result<std::unique_ptr<MutableStorage>, std::string>
  StorageImpl::createMutableStorage(
      std::shared_ptr<CommandExecutor> command_executor) {
    return createMutableStorage(std::move(command_executor),
                                *temporaryBlockStorageFactory());
  }

  expected::Result<std::unique_ptr<MutableStorage>, std::string>
  StorageImpl::createMutableStorage(
      std::shared_ptr<CommandExecutor> command_executor,
      BlockStorageFactory &storage_factory) {
    auto postgres_command_executor =
        std::dynamic_pointer_cast<PostgresCommandExecutor>(command_executor);
    if (postgres_command_executor == nullptr) {
      throw std::runtime_error("Bad PostgresCommandExecutor cast!");
    }
    // if we create mutable storage, then we intend to mutate wsv
    // this means that any state prepared before that moment is not needed
    // and must be removed to prevent locking
    tryRollback(postgres_command_executor->getSession());

    auto ms_log_manager = logManager()->getChild("MutableStorageImpl");

    auto wsv_command = std::make_unique<PostgresWsvCommand>(
        postgres_command_executor->getSession());

    auto peer_query =
        std::make_unique<PeerQueryWsv>(std::make_shared<PostgresWsvQuery>(
            postgres_command_executor->getSession(),
            ms_log_manager->getChild("WsvQuery")->getLogger()));

    auto block_index = std::make_unique<BlockIndexImpl>(
        std::make_unique<PostgresIndexer>(
            postgres_command_executor->getSession()),
        ms_log_manager->getChild("BlockIndexImpl")->getLogger());

    return std::make_unique<MutableStorageImpl>(
        ledgerState(),
        std::move(wsv_command),
        std::move(peer_query),
        std::move(block_index),
        std::move(postgres_command_executor),
        storage_factory.create().assumeValue(),
        std::move(ms_log_manager));
  }

  iroha::expected::Result<void, std::string> StorageImpl::resetPeers() {
    log()->info("Remove everything from peers table");
    soci::session sql(*connection_);
    return PgConnectionInit::resetPeers(sql);
  }

  void StorageImpl::freeConnections() {
    std::unique_lock<std::shared_timed_mutex> lock(drop_mutex_);
    if (connection_ == nullptr) {
      log()->warn("Tried to free connections without active connection");
      return;
    }
    // rollback possible prepared transaction
    {
      soci::session sql(*connection_);
      tryRollback(sql);
    }
    std::vector<std::shared_ptr<soci::session>> sessions;
    for (size_t i = 0; i < pool_size_; i++) {
      sessions.push_back(std::make_shared<soci::session>(*connection_));
      sessions.at(i)->close();
      log()->debug("Closed connection {}", i);
    }
    sessions.clear();
    connection_.reset();
  }

  expected::Result<std::shared_ptr<StorageImpl>, std::string>
  StorageImpl::create(
      const ametsuchi::PostgresOptions &postgres_options,
      std::shared_ptr<PoolWrapper> pool_wrapper,
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
      logger::LoggerManagerTreePtr log_manager,
      size_t pool_size) {
    boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state;
    {
      soci::session sql{*pool_wrapper->connection_pool_};
      PostgresWsvQuery wsv_query(
          sql, log_manager->getChild("WsvQuery")->getLogger());

      auto maybe_top_block_info = wsv_query.getTopBlockInfo();
      auto maybe_ledger_peers = wsv_query.getPeers(false);
      auto maybe_ledger_syncing_peers = wsv_query.getPeers(true);

      if (expected::hasValue(maybe_top_block_info) && maybe_ledger_peers
          && maybe_ledger_syncing_peers)
        ledger_state = std::make_shared<const iroha::LedgerState>(
            std::move(*maybe_ledger_peers),
            std::move(*maybe_ledger_syncing_peers),
            maybe_top_block_info.assumeValue().height,
            maybe_top_block_info.assumeValue().top_hash);
    }

    return expected::makeValue(std::shared_ptr<StorageImpl>(
        new StorageImpl(std::move(ledger_state),
                        std::move(postgres_options),
                        std::move(persistent_block_storage),
                        std::move(pool_wrapper),
                        perm_converter,
                        std::move(pending_txs_storage),
                        std::move(query_response_factory),
                        std::move(temporary_block_storage_factory),
                        pool_size,
                        std::move(vm_caller_ref),
                        std::move(callback),
                        std::move(log_manager))));
  }

  CommitResult StorageImpl::commitPrepared(
      std::shared_ptr<const shared_model::interface::Block> block) {
    std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
    if (not connection_) {
      std::string msg(
          "commitPrepared: connection to database is not initialised");
      return expected::makeError(std::move(msg));
    }

    soci::session sql(*connection_);
    PostgresDbTransaction db_context(sql);

    PostgresWsvCommand wsv_command{sql};
    PostgresWsvQuery wsv_query(
        sql, this->logManager()->getChild("WsvQuery")->getLogger());
    auto indexer = std::make_unique<PostgresIndexer>(sql);

    return StorageBase::commitPreparedImpl(
        block, db_context, wsv_command, wsv_query, std::move(indexer));
  }

  std::shared_ptr<WsvQuery> StorageImpl::getWsvQuery() const {
    std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
    if (not connection_) {
      log()->info("getWsvQuery: connection to database is not initialised");
      return nullptr;
    }
    return std::make_shared<PostgresWsvQuery>(
        std::make_unique<soci::session>(*connection_),
        logManager()->getChild("WsvQuery")->getLogger());
  }

  std::shared_ptr<BlockQuery> StorageImpl::getBlockQuery() const {
    std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
    if (not connection_) {
      log()->info("getBlockQuery: connection to database is not initialised");
      return nullptr;
    }
    return std::make_shared<PostgresBlockQuery>(
        std::make_unique<soci::session>(*connection_),
        *blockStore(),
        logManager()->getChild("PostgresBlockQuery")->getLogger());
  }

  boost::optional<std::unique_ptr<SettingQuery>>
  StorageImpl::createSettingQuery() const {
    std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
    if (not connection_) {
      log()->info("getSettingQuery: connection to database is not initialised");
      return boost::none;
    }
    std::unique_ptr<SettingQuery> setting_query_ptr =
        std::make_unique<PostgresSettingQuery>(
            std::make_unique<soci::session>(*connection_),
            logManager()->getChild("PostgresSettingQuery")->getLogger());
    return boost::make_optional(std::move(setting_query_ptr));
  }

  void StorageImpl::prepareBlock(std::unique_ptr<TemporaryWsv> wsv) {
    auto &wsv_impl = static_cast<PostgresTemporaryWsvImpl &>(*wsv);
    PostgresDbTransaction db_context(wsv_impl.getSession());
    StorageBase::prepareBlockImpl(std::move(wsv), db_context);
  }

  StorageImpl::~StorageImpl() {
    freeConnections();
  }

  void StorageImpl::tryRollback(soci::session &session) {
    // TODO 17.06.2019 luckychess IR-568 split connection and schema
    // initialisation
    if (blockIsPrepared()) {
      auto result =
          PgConnectionInit::rollbackPrepared(session, prepared_block_name_);
      if (iroha::expected::hasError(result)) {
        log()->info("Block rollback  error: {}", result.assumeError());
      } else {
        blockIsPrepared() = false;
      }
    }
  }

}  // namespace iroha::ametsuchi
