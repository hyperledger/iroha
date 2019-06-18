/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_impl.hpp"

#include <utility>

#include <soci/callbacks.h>
#include <soci/postgresql/soci-postgresql.h>
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include <boost/range/algorithm/replace_if.hpp>
#include "ametsuchi/impl/flat_file/flat_file.hpp"
#include "ametsuchi/impl/mutable_storage_impl.hpp"
#include "ametsuchi/impl/peer_query_wsv.hpp"
#include "ametsuchi/impl/postgres_block_index.hpp"
#include "ametsuchi/impl/postgres_block_query.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_wsv_command.hpp"
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/impl/temporary_wsv_impl.hpp"
#include "ametsuchi/tx_executor.hpp"
#include "backend/protobuf/permissions.hpp"
#include "common/bind.hpp"
#include "common/byteutils.hpp"
#include "converters/protobuf/json_proto_converter.hpp"
#include "cryptography/public_key.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"

namespace iroha {
  namespace ametsuchi {

    const char *kCommandExecutorError = "Cannot create CommandExecutorFactory";
    const char *kPsqlBroken = "Connection to PostgreSQL broken: %s";
    const char *kTmpWsv = "TemporaryWsv";

    ConnectionContext::ConnectionContext(
        std::unique_ptr<KeyValueStorage> block_store)
        : block_store(std::move(block_store)) {}

    StorageImpl::StorageImpl(
        PostgresOptions postgres_options,
        std::unique_ptr<KeyValueStorage> block_store,
        std::unique_ptr<PoolWrapper> pool_wrapper,
        std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::unique_ptr<BlockStorageFactory> block_storage_factory,
        size_t pool_size,
        const std::string &prepared_block_name,
        logger::LoggerManagerTreePtr log_manager)
        : postgres_options_(std::move(postgres_options)),
          block_store_(std::move(block_store)),
          pool_wrapper_(std::move(pool_wrapper)),
          connection_(pool_wrapper_->connection_pool_),
          factory_(std::move(factory)),
          notifier_(notifier_lifetime_),
          converter_(std::move(converter)),
          perm_converter_(std::move(perm_converter)),
          block_storage_factory_(std::move(block_storage_factory)),
          log_manager_(std::move(log_manager)),
          log_(log_manager_->getLogger()),
          pool_size_(pool_size),
          prepared_blocks_enabled_(
              pool_wrapper_->enable_prepared_transactions_),
          block_is_prepared_(false),
          prepared_block_name_(prepared_block_name) {}

    expected::Result<std::unique_ptr<TemporaryWsv>, std::string>
    StorageImpl::createTemporaryWsv() {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
      if (connection_ == nullptr) {
        return expected::makeError("Connection was closed");
      }
      auto sql = std::make_unique<soci::session>(*connection_);
      // if we create temporary storage, then we intend to validate a new
      // proposal. this means that any state prepared before that moment is
      // not needed and must be removed to prevent locking
      tryRollback(*sql);
      return expected::makeValue<std::unique_ptr<TemporaryWsv>>(
          std::make_unique<TemporaryWsvImpl>(
              std::move(sql),
              perm_converter_,
              log_manager_->getChild("TemporaryWorldStateView")));
    }

    expected::Result<std::unique_ptr<MutableStorage>, std::string>
    StorageImpl::createMutableStorage() {
      return createMutableStorage(*block_storage_factory_);
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

    boost::optional<std::shared_ptr<QueryExecutor>>
    StorageImpl::createQueryExecutor(
        std::shared_ptr<PendingTransactionStorage> pending_txs_storage,
        std::shared_ptr<shared_model::interface::QueryResponseFactory>
            response_factory) const {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
      if (not connection_) {
        log_->info(
            "createQueryExecutor: connection to database is not initialised");
        return boost::none;
      }
      return boost::make_optional<std::shared_ptr<QueryExecutor>>(
          std::make_shared<PostgresQueryExecutor>(
              std::make_unique<soci::session>(*connection_),
              *block_store_,
              std::move(pending_txs_storage),
              converter_,
              std::move(response_factory),
              perm_converter_,
              log_manager_->getChild("QueryExecutor")));
    }

    bool StorageImpl::insertBlock(
        std::shared_ptr<const shared_model::interface::Block> block) {
      log_->info("create mutable storage");
      bool inserted = false;
      createMutableStorage().match(
          [&, this](auto &&storage) {
            inserted = storage.value->apply(block);
            log_->info("block inserted: {}", inserted);
            this->commit(std::move(storage.value));
          },
          [&](const auto &error) { log_->error("{}", error.error); });
      return inserted;
    }

    expected::Result<void, std::string> StorageImpl::insertPeer(
        const shared_model::interface::Peer &peer) {
      log_->info("Insert peer {}", peer.pubkey().hex());
      soci::session sql(*connection_);
      PostgresWsvCommand wsv_command(sql);
      return wsv_command.insertPeer(peer);
    }

    expected::Result<std::unique_ptr<MutableStorage>, std::string>
    StorageImpl::createMutableStorage(BlockStorageFactory &storage_factory) {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
      if (connection_ == nullptr) {
        return expected::makeError("Connection was closed");
      }

      auto sql = std::make_unique<soci::session>(*connection_);
      // if we create mutable storage, then we intend to mutate wsv
      // this means that any state prepared before that moment is not needed
      // and must be removed to prevent locking
      tryRollback(*sql);
      shared_model::interface::types::HashType hash{""};
      shared_model::interface::types::HeightType height{0};
      auto block_query = getBlockQuery();
      if (not block_query) {
        return expected::makeError("Cannot create BlockQuery");
      }
      block_query->getBlock(block_query->getTopBlockHeight())
          .match(
              [&hash, &height](const auto &v) {
                hash = v.value->hash();
                height = v.value->height();
              },
              [this](const auto &e) {
                log_->error("Could not get top block: {}", e.error);
              });
      return expected::makeValue<std::unique_ptr<MutableStorage>>(
          std::make_unique<MutableStorageImpl>(
              hash,
              height,
              std::make_shared<TransactionExecutor>(
                  std::make_shared<PostgresCommandExecutor>(*sql,
                                                            perm_converter_)),
              std::move(sql),
              factory_,
              storage_factory.create(),
              log_manager_->getChild("MutableStorageImpl")));
    }

    void StorageImpl::reset() {
      resetWsv().match(
          [this](auto &&v) {
            log_->debug("drop blocks from disk");
            block_store_->dropAll();
          },
          [this](auto &&e) {
            log_->warn("Failed to drop WSV. Reason: {}", e.error);
          });
    }

    expected::Result<void, std::string> StorageImpl::resetWsv() {
      log_->debug("drop wsv records from db tables");
      try {
        soci::session sql(*connection_);
        // rollback possible prepared transaction
        tryRollback(sql);
        sql << reset_;
      } catch (std::exception &e) {
        return expected::makeError(e.what());
      }
      return expected::Value<void>();
    }

    void StorageImpl::resetPeers() {
      log_->info("Remove everything from peers table");
      try {
        soci::session sql(*connection_);
        sql << reset_peers_;
      } catch (std::exception &e) {
        log_->error("Failed to reset peers list, reason: {}", e.what());
      }
    }

    void StorageImpl::dropStorage() {
      log_->info("drop storage");
      if (connection_ == nullptr) {
        log_->warn("Tried to drop storage without active connection");
        return;
      }

      std::unique_lock<std::shared_timed_mutex> lock(drop_mutex_);
      log_->info("Drop database {}", postgres_options_.dbname());
      freeConnections();
      soci::session sql(*soci::factory_postgresql(),
                        postgres_options_.optionsStringWithoutDbName());
      // perform dropping
      try {
        sql << "DROP DATABASE " + postgres_options_.dbname();
      } catch (std::exception &e) {
        log_->warn("Drop database was failed. Reason: {}", e.what());
      }

      // erase blocks
      log_->info("drop block store");
      block_store_->dropAll();
    }

    void StorageImpl::freeConnections() {
      if (connection_ == nullptr) {
        log_->warn("Tried to free connections without active connection");
        return;
      }
      // rollback possible prepared transaction
      {
        soci::session sql(*connection_);
        tryRollback(sql);
      }
      std::vector<std::shared_ptr<soci::session>> connections;
      for (size_t i = 0; i < pool_size_; i++) {
        connections.push_back(std::make_shared<soci::session>(*connection_));
        connections.at(i)->close();
        log_->debug("Closed connection {}", i);
      }
      connections.clear();
      connection_.reset();
    }

    expected::Result<ConnectionContext, std::string>
    StorageImpl::initConnections(std::string block_store_dir,
                                 logger::LoggerPtr log) {
      log->info("Start storage creation");

      auto block_store = FlatFile::create(block_store_dir, log);
      if (not block_store) {
        return expected::makeError(
            (boost::format("Cannot create block store in %s") % block_store_dir)
                .str());
      }
      log->info("block store created");

      return expected::makeValue(ConnectionContext(std::move(*block_store)));
    }

    expected::Result<std::shared_ptr<StorageImpl>, std::string>
    StorageImpl::create(
        std::string block_store_dir,
        const PostgresOptions &options,
        std::unique_ptr<PoolWrapper> pool_wrapper,
        std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::unique_ptr<BlockStorageFactory> block_storage_factory,
        logger::LoggerManagerTreePtr log_manager,
        size_t pool_size) {
      std::string prepared_block_name = "prepared_block" + options.dbname();
      auto ctx_result =
          initConnections(block_store_dir, log_manager->getLogger());
      expected::Result<std::shared_ptr<StorageImpl>, std::string> storage;
      std::move(ctx_result)
          .match(
              [&](auto &&ctx) {
                storage = expected::makeValue(std::shared_ptr<StorageImpl>(
                    new StorageImpl(options,
                                    std::move(ctx.value.block_store),
                                    std::move(pool_wrapper),
                                    factory,
                                    converter,
                                    perm_converter,
                                    std::move(block_storage_factory),
                                    pool_size,
                                    prepared_block_name,
                                    std::move(log_manager))));
              },
              [&](const auto &error) { storage = error; });
      return storage;
    }

    boost::optional<std::unique_ptr<LedgerState>> StorageImpl::commit(
        std::unique_ptr<MutableStorage> mutable_storage) {
      auto storage = static_cast<MutableStorageImpl *>(mutable_storage.get());

      try {
        *(storage->sql_) << "COMMIT";
        storage->committed = true;

        storage->block_storage_->forEach(
            [this](const auto &block) { this->storeBlock(block); });

        return PostgresWsvQuery(*(storage->sql_),
                                factory_,
                                log_manager_->getChild("WsvQuery")->getLogger())
                   .getPeers()
            | [&storage](auto &&peers) {
                return boost::optional<std::unique_ptr<LedgerState>>(
                    std::make_unique<LedgerState>(std::move(peers),
                                                  storage->getTopBlockHeight(),
                                                  storage->getTopBlockHash()));
              };
      } catch (std::exception &e) {
        storage->committed = false;
        log_->warn("Mutable storage is not committed. Reason: {}", e.what());
        return boost::none;
      }
    }

    boost::optional<std::unique_ptr<LedgerState>> StorageImpl::commitPrepared(
        std::shared_ptr<const shared_model::interface::Block> block) {
      if (not prepared_blocks_enabled_) {
        log_->warn("prepared blocks are not enabled");
        return boost::none;
      }

      if (not block_is_prepared_) {
        log_->info("there are no prepared blocks");
        return boost::none;
      }
      log_->info("applying prepared block");

      try {
        std::shared_lock<std::shared_timed_mutex> lock(drop_mutex_);
        if (not connection_) {
          log_->info(
              "commitPrepared: connection to database is not initialised");
          return boost::none;
        }
        soci::session sql(*connection_);
        sql << "COMMIT PREPARED '" + prepared_block_name_ + "';";
        PostgresBlockIndex block_index(
            sql, log_manager_->getChild("BlockIndex")->getLogger());
        block_index.index(*block);
        block_is_prepared_ = false;
        return PostgresWsvQuery(sql,
                                factory_,
                                log_manager_->getChild("WsvQuery")->getLogger())
                       .getPeers()
                   | [this, &block](auto &&peers)
                   -> boost::optional<std::unique_ptr<LedgerState>> {
          if (this->storeBlock(block)) {
            return boost::optional<std::unique_ptr<LedgerState>>(
                std::make_unique<LedgerState>(
                    std::move(peers), block->height(), block->hash()));
          }
          return boost::none;
        };
      } catch (const std::exception &e) {
        log_->warn("failed to apply prepared block {}: {}",
                   block->hash().hex(),
                   e.what());
        return boost::none;
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
          factory_,
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
          converter_,
          log_manager_->getChild("PostgresBlockQuery")->getLogger());
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
        soci::session &sql = *wsv_impl.sql_;
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

    bool StorageImpl::storeBlock(
        std::shared_ptr<const shared_model::interface::Block> block) {
      return converter_->serialize(*block).match(
          [this, &block](const auto &v) {
            if (block_store_->add(block->height(), stringToBytes(v.value))) {
              notifier_.get_subscriber().on_next(block);
              return true;
            } else {
              log_->error("Block insertion failed: {}", *block);
              return false;
            }
          },
          [this, &block](const auto &e) {
            log_->error("Block serialization failed: {}: {}", *block, e.error);
            return false;
          });
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

    const std::string &StorageImpl::reset_ = R"(
TRUNCATE TABLE account_has_signatory RESTART IDENTITY CASCADE;
TRUNCATE TABLE account_has_asset RESTART IDENTITY CASCADE;
TRUNCATE TABLE role_has_permissions RESTART IDENTITY CASCADE;
TRUNCATE TABLE account_has_roles RESTART IDENTITY CASCADE;
TRUNCATE TABLE account_has_grantable_permissions RESTART IDENTITY CASCADE;
TRUNCATE TABLE account RESTART IDENTITY CASCADE;
TRUNCATE TABLE asset RESTART IDENTITY CASCADE;
TRUNCATE TABLE domain RESTART IDENTITY CASCADE;
TRUNCATE TABLE signatory RESTART IDENTITY CASCADE;
TRUNCATE TABLE peer RESTART IDENTITY CASCADE;
TRUNCATE TABLE role RESTART IDENTITY CASCADE;
TRUNCATE TABLE position_by_hash RESTART IDENTITY CASCADE;
TRUNCATE TABLE tx_status_by_hash RESTART IDENTITY CASCADE;
TRUNCATE TABLE height_by_account_set RESTART IDENTITY CASCADE;
TRUNCATE TABLE index_by_creator_height RESTART IDENTITY CASCADE;
TRUNCATE TABLE position_by_account_asset RESTART IDENTITY CASCADE;
)";

    const std::string &StorageImpl::reset_peers_ = R"(
TRUNCATE TABLE peer RESTART IDENTITY CASCADE;
)";
  }  // namespace ametsuchi
}  // namespace iroha
