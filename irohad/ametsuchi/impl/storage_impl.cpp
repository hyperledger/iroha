/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_impl.hpp"

#include <soci/callbacks.h>
#include <soci/postgresql/soci-postgresql.h>

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/range/algorithm/replace_if.hpp>
#include <boost/tuple/tuple.hpp>

#include "ametsuchi/impl/mutable_storage_impl.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_block_index.hpp"
#include "ametsuchi/impl/postgres_block_query.hpp"
#include "ametsuchi/impl/postgres_block_storage_factory.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_setting_query.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/impl/temporary_wsv_impl.hpp"
#include "ametsuchi/ledger_state.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "backend/protobuf/permissions.hpp"
#include "common/bind.hpp"
#include "common/byteutils.hpp"
#include "common/result.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/subscription.hpp"

namespace iroha {
  namespace ametsuchi {

    const char *kCommandExecutorError = "Cannot create CommandExecutorFactory";
    const char *kPsqlBroken = "Connection to PostgreSQL broken: %s";
    const char *kTmpWsv = "TemporaryWsv";

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
        logger::LoggerManagerTreePtr log_manager)
        : block_store_(std::move(block_store)),
          pool_wrapper_(std::move(pool_wrapper)),
          connection_(pool_wrapper_->connection_pool_),
          notifier_(notifier_lifetime_),
          perm_converter_(std::move(perm_converter)),
          pending_txs_storage_(std::move(pending_txs_storage)),
          query_response_factory_(std::move(query_response_factory)),
          temporary_block_storage_factory_(
              std::move(temporary_block_storage_factory)),
          vm_caller_ref_(std::move(vm_caller_ref)),
          log_manager_(std::move(log_manager)),
          log_(log_manager_->getLogger()),
          pool_size_(pool_size),
          prepared_blocks_enabled_(
              pool_wrapper_->enable_prepared_transactions_),
          block_is_prepared_(false),
          prepared_block_name_(postgres_options.preparedBlockName()),
          ledger_state_(std::move(ledger_state)) {}

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
      return std::make_unique<TemporaryWsvImpl>(
          std::move(postgres_command_executor),
          log_manager_->getChild("TemporaryWorldStateView"));
    }

    expected::Result<std::unique_ptr<MutableStorage>, std::string>
    StorageImpl::createMutableStorage(
        std::shared_ptr<CommandExecutor> command_executor) {
      return createMutableStorage(std::move(command_executor),
                                  *temporary_block_storage_factory_);
    }

    boost::optional<std::shared_ptr<PeerQuery>> StorageImpl::createPeerQuery()
        const {
      auto wsv = getWsvQuery();
      if (not wsv) {
        return boost::none;
      }
      return boost::make_optional<std::shared_ptr<PeerQuery>>(
          std::make_shared<PeerQueryWsv>(wsv));
    }

    boost::optional<std::shared_ptr<BlockQuery>> StorageImpl::createBlockQuery()
        const {
      auto block_query = getBlockQuery();
      if (not block_query) {
        return boost::none;
      }
      return boost::make_optional(block_query);
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
      auto log_manager = log_manager_->getChild("QueryExecutor");
      return std::make_unique<PostgresQueryExecutor>(
          std::move(sql),
          response_factory,
          std::make_shared<PostgresSpecificQueryExecutor>(
              *sql,
              *block_store_,
              std::move(pending_txs_storage),
              response_factory,
              perm_converter_,
              log_manager->getChild("SpecificQueryExecutor")->getLogger()),
          log_manager->getLogger());
    }

    expected::Result<void, std::string> StorageImpl::insertBlock(
        std::shared_ptr<const shared_model::interface::Block> block) {
      log_->info("create mutable storage");
      return createCommandExecutor() | [&](auto &&command_executor) {
        return createMutableStorage(std::move(command_executor)) |
                   [&](auto &&mutable_storage)
                   -> expected::Result<void, std::string> {
          const bool is_inserted = mutable_storage->apply(block);
          commit(std::move(mutable_storage));
          if (is_inserted) {
            return {};
          }
          return "Stateful validation failed.";
        };
      };
    }

    expected::Result<void, std::string> StorageImpl::insertPeer(
        const shared_model::interface::Peer &peer) {
      log_->info("Insert peer {}", peer.pubkey());
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
          perm_converter_,
          std::make_shared<PostgresSpecificQueryExecutor>(
              *sql,
              *block_store_,
              pending_txs_storage_,
              query_response_factory_,
              perm_converter_,
              log_manager_->getChild("SpecificQueryExecutor")->getLogger()),
          vm_caller_ref_);
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
      return std::make_unique<MutableStorageImpl>(
          ledger_state_,
          std::move(postgres_command_executor),
          storage_factory.create().assumeValue(),
          log_manager_->getChild("MutableStorageImpl"));
    }

    void StorageImpl::resetPeers() {
      log_->info("Remove everything from peers table");
      soci::session sql(*connection_);
      expected::resultToOptionalError(PgConnectionInit::resetPeers(sql)) |
          [this](const auto &e) { this->log_->error("{}", e); };
    }

    expected::Result<void, std::string> StorageImpl::dropBlockStorage() {
      log_->info("drop block storage");
      block_store_->clear();
      return iroha::expected::Value<void>{};
    }

    boost::optional<std::shared_ptr<const iroha::LedgerState>>
    StorageImpl::getLedgerState() const {
      return ledger_state_;
    }

    void StorageImpl::freeConnections() {
      std::unique_lock<std::shared_timed_mutex> lock(drop_mutex_);
      if (connection_ == nullptr) {
        log_->warn("Tried to free connections without active connection");
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
        log_->debug("Closed connection {}", i);
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
        logger::LoggerManagerTreePtr log_manager,
        size_t pool_size) {
      boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state;
      {
        soci::session sql{*pool_wrapper->connection_pool_};
        PostgresWsvQuery wsv_query(
            sql, log_manager->getChild("WsvQuery")->getLogger());

        ledger_state =
            expected::resultToOptionalValue(wsv_query.getTopBlockInfo()) |
            [&](auto &&top_block_info) {
              return wsv_query.getPeers() |
                  [&top_block_info](auto &&ledger_peers) {
                    return boost::make_optional(
                        std::make_shared<const iroha::LedgerState>(
                            std::move(ledger_peers),
                            top_block_info.height,
                            top_block_info.top_hash));
                  };
            };
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
                          std::move(log_manager))));
    }

    CommitResult StorageImpl::commit(
        std::unique_ptr<MutableStorage> mutable_storage) {
      auto old_height = block_store_->size();
      return std::move(*mutable_storage).commit(*block_store_) |
                 [this, old_height](auto commit_result) -> CommitResult {
        ledger_state_ = commit_result.ledger_state;
        auto new_height = block_store_->size();
        for (auto height = old_height + 1; height <= new_height; ++height) {
          auto maybe_block = block_store_->fetch(height);
          if (not maybe_block) {
            return fmt::format("Failed to fetch block {}", height);
          }

          std::shared_ptr<const shared_model::interface::Block> block_ptr =
              std::move(maybe_block.get());
          notifier_.get_subscriber().on_next(block_ptr);
          getSubscription()->notify(EventTypes::kOnBlock, block_ptr);
        }
        return expected::makeValue(std::move(commit_result.ledger_state));
      };
    }

    bool StorageImpl::preparedCommitEnabled() const {
      return prepared_blocks_enabled_ and block_is_prepared_;
    }

    CommitResult StorageImpl::commitPrepared(
        std::shared_ptr<const shared_model::interface::Block> block) {
      if (not prepared_blocks_enabled_) {
        return expected::makeError(
            std::string{"prepared blocks are not enabled"});
      }

      if (not block_is_prepared_) {
        return expected::makeError("there are no prepared blocks");
      }

      log_->info("applying prepared block");

      try {
        std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
        if (not connection_) {
          std::string msg(
              "commitPrepared: connection to database is not initialised");
          return expected::makeError(std::move(msg));
        }

        if (not block_store_->insert(block)) {
          return fmt::format("Failed to insert block {}", *block);
        }

        soci::session sql(*connection_);
        sql << "COMMIT PREPARED '" + prepared_block_name_ + "';";
        PostgresBlockIndex block_index(
            std::make_unique<PostgresIndexer>(sql),
            log_manager_->getChild("BlockIndex")->getLogger());
        block_index.index(*block);
        block_is_prepared_ = false;

        if (auto e = expected::resultToOptionalError(
                PostgresWsvCommand{sql}.setTopBlockInfo(
                    TopBlockInfo{block->height(), block->hash()}))) {
          throw std::runtime_error(e.value());
        }

        notifier_.get_subscriber().on_next(block);
        getSubscription()->notify(
            EventTypes::kOnBlock,
            std::shared_ptr<const shared_model::interface::Block>(block));

        decltype(std::declval<PostgresWsvQuery>().getPeers()) opt_ledger_peers;
        {
          auto peer_query = PostgresWsvQuery(
              sql, this->log_manager_->getChild("WsvQuery")->getLogger());
          if (not(opt_ledger_peers = peer_query.getPeers())) {
            return expected::makeError(
                std::string{"Failed to get ledger peers! Will retry."});
          }
        }
        assert(opt_ledger_peers);

        ledger_state_ = std::make_shared<const LedgerState>(
            std::move(*opt_ledger_peers), block->height(), block->hash());
        return expected::makeValue(ledger_state_.value());
      } catch (const std::exception &e) {
        std::string msg((boost::format("failed to apply prepared block %s: %s")
                         % block->hash().hex() % e.what())
                            .str());
        return expected::makeError(msg);
      }
    }

    std::shared_ptr<WsvQuery> StorageImpl::getWsvQuery() const {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
      if (not connection_) {
        log_->info("getWsvQuery: connection to database is not initialised");
        return nullptr;
      }
      return std::make_shared<PostgresWsvQuery>(
          std::make_unique<soci::session>(*connection_),
          log_manager_->getChild("WsvQuery")->getLogger());
    }

    std::shared_ptr<BlockQuery> StorageImpl::getBlockQuery() const {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
      if (not connection_) {
        log_->info("getBlockQuery: connection to database is not initialised");
        return nullptr;
      }
      return std::make_shared<PostgresBlockQuery>(
          std::make_unique<soci::session>(*connection_),
          *block_store_,
          log_manager_->getChild("PostgresBlockQuery")->getLogger());
    }

    boost::optional<std::unique_ptr<SettingQuery>>
    StorageImpl::createSettingQuery() const {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
      if (not connection_) {
        log_->info(
            "getSettingQuery: connection to database is not initialised");
        return boost::none;
      }
      std::unique_ptr<SettingQuery> setting_query_ptr =
          std::make_unique<PostgresSettingQuery>(
              std::make_unique<soci::session>(*connection_),
              log_manager_->getChild("PostgresSettingQuery")->getLogger());
      return boost::make_optional(std::move(setting_query_ptr));
    }

    rxcpp::observable<std::shared_ptr<const shared_model::interface::Block>>
    StorageImpl::on_commit() {
      return notifier_.get_observable();
    }

    void StorageImpl::prepareBlock(std::unique_ptr<TemporaryWsv> wsv) {
      auto &wsv_impl = static_cast<TemporaryWsvImpl &>(*wsv);
      if (not prepared_blocks_enabled_) {
        log_->warn("prepared blocks are not enabled");
        return;
      }
      if (block_is_prepared_) {
        log_->warn(
            "Refusing to add new prepared state, because there already is one. "
            "Multiple prepared states are not yet supported.");
      } else {
        soci::session &sql = wsv_impl.sql_;
        try {
          sql << "PREPARE TRANSACTION '" + prepared_block_name_ + "';";
          block_is_prepared_ = true;
        } catch (const std::exception &e) {
          log_->warn("failed to prepare state: {}", e.what());
        }

        log_->info("state prepared successfully");
      }
    }

    StorageImpl::~StorageImpl() {
      notifier_lifetime_.unsubscribe();
      freeConnections();
    }

    StorageImpl::StoreBlockResult StorageImpl::storeBlock(
        std::shared_ptr<const shared_model::interface::Block> block) {
      if (block_store_->insert(block)) {
        notifier_.get_subscriber().on_next(block);
        getSubscription()->notify(
            EventTypes::kOnBlock,
            std::shared_ptr<const shared_model::interface::Block>(block));
        return {};
      }
      return expected::makeError("Block insertion to storage failed");
    }

    void StorageImpl::tryRollback(soci::session &session) {
      // TODO 17.06.2019 luckychess IR-568 split connection and schema
      // initialisation
      if (block_is_prepared_) {
        PgConnectionInit::rollbackPrepared(session, prepared_block_name_)
            .match([this](auto &&v) { block_is_prepared_ = false; },
                   [this](auto &&e) {
                     log_->info("Block rollback  error: {}",
                                std::move(e.error));
                   });
      }
    }

  }  // namespace ametsuchi
}  // namespace iroha
