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
#include "ametsuchi/impl/postgres_indexer.hpp"
#include "ametsuchi/impl/postgres_query_executor.hpp"
#include "ametsuchi/impl/postgres_specific_query_executor.hpp"
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
        boost::optional<std::shared_ptr<const iroha::LedgerState>> ledger_state,
        std::unique_ptr<ametsuchi::PostgresOptions> postgres_options,
        std::unique_ptr<KeyValueStorage> block_store,
        PoolWrapper pool_wrapper,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::unique_ptr<BlockStorageFactory> block_storage_factory,
        size_t pool_size,
        logger::LoggerManagerTreePtr log_manager)
        : postgres_options_(std::move(postgres_options)),
          block_store_(std::move(block_store)),
          pool_wrapper_(std::move(pool_wrapper)),
          connection_(pool_wrapper_.connection_pool_),
          notifier_(notifier_lifetime_),
          converter_(std::move(converter)),
          perm_converter_(std::move(perm_converter)),
          block_storage_factory_(std::move(block_storage_factory)),
          log_manager_(std::move(log_manager)),
          log_(log_manager_->getLogger()),
          pool_size_(pool_size),
          prepared_blocks_enabled_(pool_wrapper_.enable_prepared_transactions_),
          block_is_prepared_(false),
          prepared_block_name_(postgres_options_->preparedBlockName()),
          ledger_state_(std::move(ledger_state)) {}

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
              std::make_unique<TransactionExecutor>(
                  std::make_unique<PostgresCommandExecutor>(*sql,
                                                            perm_converter_)),

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
      auto sql = std::make_unique<soci::session>(*connection_);
      auto log_manager = log_manager_->getChild("QueryExecutor");
      return boost::make_optional<std::shared_ptr<QueryExecutor>>(
          std::make_shared<PostgresQueryExecutor>(
              std::move(sql),
              response_factory,
              std::make_shared<PostgresSpecificQueryExecutor>(
                  *sql,
                  *block_store_,
                  std::move(pending_txs_storage),
                  converter_,
                  response_factory,
                  perm_converter_,
                  log_manager->getChild("SpecificQueryExecutor")->getLogger()),
              log_manager->getLogger()));
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
      return expected::makeValue<std::unique_ptr<MutableStorage>>(
          std::make_unique<MutableStorageImpl>(
              ledger_state_,
              std::make_shared<TransactionExecutor>(
                  std::make_shared<PostgresCommandExecutor>(*sql,
                                                            perm_converter_)),
              std::move(sql),
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
        return PgConnectionInit::resetWsv(sql);
      } catch (std::exception &e) {
        return expected::makeError(e.what());
      }
    }

    void StorageImpl::resetPeers() {
      log_->info("Remove everything from peers table");
      soci::session sql(*connection_);
      expected::resultToOptionalError(PgConnectionInit::resetPeers(sql)) |
          [this](const auto &e) { this->log_->error("{}", e); };
    }

    void StorageImpl::dropStorage() {
      log_->info("drop storage");
      if (connection_ == nullptr) {
        log_->warn("Tried to drop storage without active connection");
        return;
      }

      std::unique_lock<std::shared_timed_mutex> lock(drop_mutex_);
      log_->info("Drop database {}", postgres_options_->workingDbName());
      freeConnections();
      if (auto e = expected::resultToOptionalError(
              PgConnectionInit::dropWorkingDatabase(*postgres_options_))) {
        log_->warn(e.value());
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
        std::unique_ptr<ametsuchi::PostgresOptions> postgres_options,
        PoolWrapper pool_wrapper,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::unique_ptr<BlockStorageFactory> block_storage_factory,
        logger::LoggerManagerTreePtr log_manager,
        size_t pool_size) {
      return initConnections(block_store_dir, log_manager->getLogger()) |
          [&](auto &&ctx) {
            auto opt_ledger_state = [&] {
              soci::session sql{*pool_wrapper.connection_pool_};

              using BlockInfoResult =
                  expected::Result<iroha::TopBlockInfo, std::string>;
              auto get_top_block_info = [&]() -> BlockInfoResult {
                PostgresBlockQuery block_query(
                    sql,
                    *ctx.block_store,
                    converter,
                    log_manager->getChild("PostgresBlockQuery")->getLogger());
                const auto ledger_height = block_query.getTopBlockHeight();
                return block_query.getBlock(ledger_height)
                    .match(
                        [&ledger_height](const auto &block) -> BlockInfoResult {
                          return expected::makeValue(iroha::TopBlockInfo{
                              ledger_height, block.value->hash()});
                        },
                        [](auto &&err) -> BlockInfoResult {
                          return std::move(err).error.message;
                        });
              };

              auto get_ledger_peers =
                  [&]() -> expected::Result<std::vector<std::shared_ptr<
                                                shared_model::interface::Peer>>,
                                            std::string> {
                PostgresWsvQuery peer_query(
                    sql, log_manager->getChild("WsvQuery")->getLogger());
                auto peers = peer_query.getPeers();
                if (peers) {
                  return expected::makeValue(std::move(peers.value()));
                }
                return expected::makeError(
                    std::string{"Failed to get ledger peers!"});
              };

              return expected::resultToOptionalValue(
                  get_top_block_info() | [&](auto &&top_block_info) {
                    return get_ledger_peers().match(
                        [&top_block_info](auto &&ledger_peers_value)
                            -> expected::Result<
                                std::shared_ptr<const iroha::LedgerState>,
                                std::string> {
                          return expected::makeValue(
                              std::make_shared<const iroha::LedgerState>(
                                  std::move(ledger_peers_value).value,
                                  top_block_info.height,
                                  top_block_info.top_hash));
                        },
                        [](auto &&e)
                            -> expected::Result<
                                std::shared_ptr<const iroha::LedgerState>,
                                std::string> { return e; });
                  });
            }();

            return expected::makeValue(std::shared_ptr<StorageImpl>(
                new StorageImpl(std::move(opt_ledger_state),
                                std::move(postgres_options),
                                std::move(ctx.block_store),
                                std::move(pool_wrapper),
                                converter,
                                perm_converter,
                                std::move(block_storage_factory),
                                pool_size,
                                std::move(log_manager))));
          };
    }

    CommitResult StorageImpl::commit(
        std::unique_ptr<MutableStorage> mutable_storage) {
      auto storage = static_cast<MutableStorageImpl *>(mutable_storage.get());

      try {
        *(storage->sql_) << "COMMIT";
      } catch (std::exception &e) {
        storage->committed = false;
        return expected::makeError(e.what());
      }
      storage->committed = true;

      storage->block_storage_->forEach(
          [this](const auto &block) { this->storeBlock(block); });

      ledger_state_ = storage->getLedgerState();
      if (ledger_state_) {
        return expected::makeValue(ledger_state_.value());
      } else {
        return expected::makeError(
            "This should never happen - a missing ledger state after a "
            "successful commit!");
      }
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
        soci::session sql(*connection_);
        sql << "COMMIT PREPARED '" + prepared_block_name_ + "';";
        PostgresBlockIndex block_index(
            std::make_unique<PostgresIndexer>(sql),
            log_manager_->getChild("BlockIndex")->getLogger());
        block_index.index(*block);
        block_is_prepared_ = false;

        return storeBlock(block) | [this, &sql, &block]() -> CommitResult {
          decltype(
              std::declval<PostgresWsvQuery>().getPeers()) opt_ledger_peers;
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
        };
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

    StorageImpl::StoreBlockResult StorageImpl::storeBlock(
        std::shared_ptr<const shared_model::interface::Block> block) {
      return converter_->serialize(*block).match(
          [this, &block](const auto &v) -> StoreBlockResult {
            if (block_store_->add(block->height(), stringToBytes(v.value))) {
              notifier_.get_subscriber().on_next(block);
              return {};
            } else {
              return expected::makeError(
                  (boost::format("Block insertion failed: %s")
                   % block->toString())
                      .str());
            }
          },
          [&block](const auto &e) -> StoreBlockResult {
            return expected::makeError(
                (boost::format("Block serialization failed: %s: %s")
                 % block->toString() % e.error)
                    .str());
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

  }  // namespace ametsuchi
}  // namespace iroha
