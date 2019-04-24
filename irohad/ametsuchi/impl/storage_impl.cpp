/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/storage_impl.hpp"

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
#include "ametsuchi/impl/postgres_wsv_query.hpp"
#include "ametsuchi/impl/temporary_wsv_impl.hpp"
#include "backend/protobuf/permissions.hpp"
#include "common/bind.hpp"
#include "common/byteutils.hpp"
#include "converters/protobuf/json_proto_converter.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace {
  void prepareStatements(soci::connection_pool &connections, size_t pool_size) {
    for (size_t i = 0; i != pool_size; i++) {
      soci::session &session = connections.at(i);
      iroha::ametsuchi::PostgresCommandExecutor::prepareStatements(session);
    }
  }

  /**
   * Verify whether postgres supports prepared transactions
   */
  bool preparedTransactionsAvailable(soci::session &sql) {
    int prepared_txs_count = 0;
    try {
      sql << "SHOW max_prepared_transactions;", soci::into(prepared_txs_count);
      return prepared_txs_count != 0;
    } catch (std::exception &e) {
      return false;
    }
  }

  std::string formatPostgresMessage(const char *message) {
    std::string formatted_message(message);
    boost::replace_if(formatted_message, boost::is_any_of("\r\n"), ' ');
    return formatted_message;
  }

  void processPqNotice(void *arg, const char *message) {
    auto *log = reinterpret_cast<logger::Logger *>(arg);
    log->debug("{}", formatPostgresMessage(message));
  }

}  // namespace

namespace iroha {
  namespace ametsuchi {
    const char *kCommandExecutorError = "Cannot create CommandExecutorFactory";
    const char *kPsqlBroken = "Connection to PostgreSQL broken: %s";
    const char *kTmpWsv = "TemporaryWsv";

    ConnectionContext::ConnectionContext(
        std::unique_ptr<KeyValueStorage> block_store)
        : block_store(std::move(block_store)) {}

    StorageImpl::StorageImpl(
        std::string block_store_dir,
        PostgresOptions postgres_options,
        std::unique_ptr<KeyValueStorage> block_store,
        std::shared_ptr<soci::connection_pool> connection,
        std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::unique_ptr<BlockStorageFactory> block_storage_factory,
        size_t pool_size,
        bool enable_prepared_blocks,
        logger::LoggerManagerTreePtr log_manager)
        : block_store_dir_(std::move(block_store_dir)),
          postgres_options_(std::move(postgres_options)),
          block_store_(std::move(block_store)),
          connection_(std::move(connection)),
          factory_(std::move(factory)),
          notifier_(notifier_lifetime_),
          converter_(std::move(converter)),
          perm_converter_(std::move(perm_converter)),
          block_storage_factory_(std::move(block_storage_factory)),
          log_manager_(std::move(log_manager)),
          log_(log_manager_->getLogger()),
          pool_size_(pool_size),
          prepared_blocks_enabled_(enable_prepared_blocks),
          block_is_prepared(false) {
      prepared_block_name_ =
          "prepared_block" + postgres_options_.dbname().value_or("");

      for (size_t i = 0; i != pool_size_; i++) {
        soci::session &session = connection_->at(i);
        auto *backend = static_cast<soci::postgresql_session_backend *>(
            session.get_backend());
        PQsetNoticeProcessor(backend->conn_, &processPqNotice, log_.get());
      }

      soci::session sql(*connection_);
      // rollback current prepared transaction
      // if there exists any since last session
      if (prepared_blocks_enabled_) {
        rollbackPrepared(sql);
      }
      try {
        sql << init_;
        prepareStatements(*connection_, pool_size_);
      } catch (std::exception &e) {
        log_->error("Storage was not initialized. Reason: {}", e.what());
      }
    }

    expected::Result<std::unique_ptr<TemporaryWsv>, std::string>
    StorageImpl::createTemporaryWsv() {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex);
      if (connection_ == nullptr) {
        return expected::makeError("Connection was closed");
      }
      auto sql = std::make_unique<soci::session>(*connection_);
      // if we create temporary storage, then we intend to validate a new
      // proposal. this means that any state prepared before that moment is not
      // needed and must be removed to prevent locking
      if (block_is_prepared) {
        rollbackPrepared(*sql);
      }

      return expected::makeValue<std::unique_ptr<TemporaryWsv>>(
          std::make_unique<TemporaryWsvImpl>(
              std::move(sql),
              factory_,
              perm_converter_,
              log_manager_->getChild("TemporaryWorldStateView")));
    }

    expected::Result<std::unique_ptr<MutableStorage>, std::string>
    StorageImpl::createMutableStorage() {
      boost::optional<shared_model::interface::types::HashType> top_hash;

      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex);
      if (connection_ == nullptr) {
        return expected::makeError("Connection was closed");
      }

      auto sql = std::make_unique<soci::session>(*connection_);
      // if we create mutable storage, then we intend to mutate wsv
      // this means that any state prepared before that moment is not needed
      // and must be removed to prevent locking
      if (block_is_prepared) {
        rollbackPrepared(*sql);
      }
      shared_model::interface::types::HashType hash{""};
      shared_model::interface::types::HeightType height{0};
      getBlockQuery()->getTopBlock().match(
          [&hash, &height](const expected::Value<std::shared_ptr<
                               const shared_model::interface::Block>> &block) {
            hash = block.value->hash();
            height = block.value->height();
          },
          [this](const expected::Error<std::string> &e) {
            log_->error("Could not get top block: {}", e.error);
          });
      return expected::makeValue<std::unique_ptr<MutableStorage>>(
          std::make_unique<MutableStorageImpl>(
              hash,
              height,
              std::make_shared<PostgresCommandExecutor>(*sql, perm_converter_),
              std::move(sql),
              factory_,
              block_storage_factory_->create(),
              log_manager_->getChild("MutableStorageImpl")));
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
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex);
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
      std::array<std::shared_ptr<const shared_model::interface::Block>, 1>
          block_array({block});
      return insertBlocks(block_array);
    }

    bool StorageImpl::insertBlocks(
        const shared_model::interface::types::SharedBlocksForwardRange
            &blocks) {
      log_->trace("Creating mutable storage.");
      return createMutableStorage().match(
          [&](expected::Value<std::unique_ptr<ametsuchi::MutableStorage>>
                  &value) {
            auto storage = std::move(value.value);
            auto blocks_string = shared_model::detail::PrettyStringBuilder{}
                                     .appendAll(blocks)
                                     .finalize();
            return std::all_of(blocks.begin(),
                               blocks.end(),
                               [this, &storage](const auto &block) -> bool {
                                 const bool applied = storage->apply(block);
                                 if (not applied) {
                                   log_->error(
                                       "Block could not be applied to "
                                       "MutableStorage: {}.",
                                       block->hash());
                                   log_->debug(
                                       "The block that could not be applied to "
                                       "MutableStorage is {}.",
                                       block);
                                 }
                                 return applied;
                               })
                and this->commit(std::move(storage))
                        .match(
                            [this, &blocks_string](auto &) {
                              log_->debug("blocks inserted: {}", blocks_string);
                              return true;
                            },
                            [this, &blocks_string](const auto &error) {
                              log_->error(
                                  "Blocks successfully applied to "
                                  "MutableStorage were not "
                                  "committed in StorageImpl: {} {}",
                                  error.error,
                                  blocks_string);
                              return false;
                            });
          },
          [&](expected::Error<std::string> &error) {
            log_->error(error.error);
            return false;
          });
    }

    void StorageImpl::reset() {
      log_->info("drop wsv records from db tables");
      try {
        soci::session sql(*connection_);
        // rollback possible prepared transaction
        if (block_is_prepared) {
          rollbackPrepared(sql);
        }
        sql << reset_;
        log_->info("drop blocks from disk");
        block_store_->dropAll();
      } catch (std::exception &e) {
        log_->warn("Drop wsv was failed. Reason: {}", e.what());
      }
    }

    void StorageImpl::dropStorage() {
      log_->info("drop storage");
      if (connection_ == nullptr) {
        log_->warn("Tried to drop storage without active connection");
        return;
      }

      if (auto dbname = postgres_options_.dbname()) {
        auto &db = dbname.value();
        std::unique_lock<std::shared_timed_mutex> lock(drop_mutex);
        log_->info("Drop database {}", db);
        freeConnections();
        soci::session sql(*soci::factory_postgresql(),
                          postgres_options_.optionsStringWithoutDbName());
        // perform dropping
        try {
          sql << "DROP DATABASE " + db;
        } catch (std::exception &e) {
          log_->warn("Drop database was failed. Reason: {}", e.what());
        }
      } else {
        // Clear all the tables first, as it takes much less time because the
        // foreign key triggers are ignored.
        soci::session(*connection_) << reset_;
        // Empty tables can now be dropped very fast.
        soci::session(*connection_) << drop_;
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
      if (block_is_prepared) {
        soci::session sql(*connection_);
        rollbackPrepared(sql);
      }
      std::vector<std::shared_ptr<soci::session>> connections;
      for (size_t i = 0; i < pool_size_; i++) {
        connections.push_back(std::make_shared<soci::session>(*connection_));
        connections[i]->close();
        log_->debug("Closed connection {}", i);
      }
      connections.clear();
      connection_.reset();
    }

    expected::Result<bool, std::string> StorageImpl::createDatabaseIfNotExist(
        const std::string &dbname,
        const std::string &options_str_without_dbname) {
      try {
        soci::session sql(*soci::factory_postgresql(),
                          options_str_without_dbname);

        int size;
        std::string name = dbname;

        sql << "SELECT count(datname) FROM pg_catalog.pg_database WHERE "
               "datname = :dbname",
            soci::into(size), soci::use(name);

        if (size == 0) {
          std::string query = "CREATE DATABASE ";
          query += dbname;
          sql << query;
          return expected::makeValue(true);
        }
        return expected::makeValue(false);
      } catch (std::exception &e) {
        return expected::makeError<std::string>(
            std::string("Connection to PostgreSQL broken: ")
            + formatPostgresMessage(e.what()));
      }
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

    expected::Result<std::shared_ptr<soci::connection_pool>, std::string>
    StorageImpl::initPostgresConnection(std::string &options_str,
                                        size_t pool_size) {
      auto pool = std::make_shared<soci::connection_pool>(pool_size);

      try {
        for (size_t i = 0; i != pool_size; i++) {
          soci::session &session = pool->at(i);
          session.open(*soci::factory_postgresql(), options_str);
        }
      } catch (const std::exception &e) {
        return expected::makeError(formatPostgresMessage(e.what()));
      }
      return expected::makeValue(pool);
    }

    expected::Result<std::shared_ptr<StorageImpl>, std::string>
    StorageImpl::create(
        std::string block_store_dir,
        std::string postgres_options,
        std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::unique_ptr<BlockStorageFactory> block_storage_factory,
        logger::LoggerManagerTreePtr log_manager,
        size_t pool_size) {
      boost::optional<std::string> string_res = boost::none;

      PostgresOptions options(postgres_options);

      // create database if
      options.dbname() | [&options, &string_res](const std::string &dbname) {
        createDatabaseIfNotExist(dbname, options.optionsStringWithoutDbName())
            .match([](expected::Value<bool> &val) {},
                   [&string_res](expected::Error<std::string> &error) {
                     string_res = error.error;
                   });
      };

      if (string_res) {
        return expected::makeError(string_res.value());
      }

      auto ctx_result =
          initConnections(block_store_dir, log_manager->getLogger());
      auto db_result = initPostgresConnection(postgres_options, pool_size);
      expected::Result<std::shared_ptr<StorageImpl>, std::string> storage;
      ctx_result.match(
          [&](expected::Value<ConnectionContext> &ctx) {
            db_result.match(
                [&](expected::Value<std::shared_ptr<soci::connection_pool>>
                        &connection) {
                  soci::session sql(*connection.value);
                  bool enable_prepared_transactions =
                      preparedTransactionsAvailable(sql);
                  storage = expected::makeValue(std::shared_ptr<StorageImpl>(
                      new StorageImpl(block_store_dir,
                                      options,
                                      std::move(ctx.value.block_store),
                                      connection.value,
                                      factory,
                                      converter,
                                      perm_converter,
                                      std::move(block_storage_factory),
                                      pool_size,
                                      enable_prepared_transactions,
                                      std::move(log_manager))));
                },
                [&](expected::Error<std::string> &error) { storage = error; });
          },
          [&](expected::Error<std::string> &error) { storage = error; });
      return storage;
    }

    CommitStatus StorageImpl::commit(
        std::unique_ptr<MutableStorage> mutable_storage) {
      auto storage = static_cast<MutableStorageImpl *>(mutable_storage.get());

      try {
        *(storage->sql_) << "COMMIT";
      } catch (std::exception &e) {
        storage->committed = false;
        log_->warn("Mutable storage is not committed. Reason: {}", e.what());
        return expected::makeError(e.what());
      }
      storage->committed = true;

      shared_model::interface::types::HeightType top_height;
      shared_model::crypto::Hash top_hash;
      storage->block_storage_->forEach(
          [this, &top_height, &top_hash](const auto &block) {
            this->storeBlock(block);
            top_height = block->height();
            top_hash = block->hash();
          });

      decltype(std::declval<PostgresWsvQuery>().getPeers()) opt_ledger_peers;
      {
        auto peer_query =
            PostgresWsvQuery(*(storage->sql_),
                             factory_,
                             log_manager_->getChild("WsvQuery")->getLogger());
        while (not(opt_ledger_peers = peer_query.getPeers())) {
          log_->error("Failed to get ledger peers! Will retry.");
        }
      }
      assert(opt_ledger_peers);

      return expected::makeValue(std::make_shared<LedgerState>(
          std::move(*opt_ledger_peers), top_height, top_hash));
    }

    boost::optional<std::unique_ptr<LedgerState>> StorageImpl::commitPrepared(
        std::shared_ptr<const shared_model::interface::Block> block) {
      if (not prepared_blocks_enabled_) {
        log_->warn("prepared blocks are not enabled");
        return boost::none;
      }

      if (not block_is_prepared) {
        log_->info("there are no prepared blocks");
        return boost::none;
      }
      log_->info("applying prepared block");

      try {
        std::shared_lock<std::shared_timed_mutex> lock(drop_mutex);
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
        block_is_prepared = false;

        if (this->storeBlock(block)) {

          decltype(
              std::declval<PostgresWsvQuery>().getPeers()) opt_ledger_peers;
          {
            auto peer_query = PostgresWsvQuery(
                sql, factory_, log_manager_->getChild("WsvQuery")->getLogger());
            while (not(opt_ledger_peers = peer_query.getPeers())) {
              log_->error("Failed to get ledger peers! Will retry.");
            }
          }
          assert(opt_ledger_peers);

          return boost::optional<std::unique_ptr<LedgerState>>(
              std::make_unique<LedgerState>(std::move(*opt_ledger_peers),
                                            block->height(),
                                            block->hash()));
        }
        return boost::none;
      } catch (const std::exception &e) {
        log_->warn("failed to apply prepared block {}: {}",
                   block->hash().hex(),
                   e.what());
        return boost::none;
      }
    }

    std::shared_ptr<WsvQuery> StorageImpl::getWsvQuery() const {
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex);
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
      std::shared_lock<std::shared_timed_mutex> lock(drop_mutex);
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
      if (block_is_prepared) {
        log_->warn(
            "Refusing to add new prepared state, because there already is one. "
            "Multiple prepared states are not yet supported.");
      } else {
        soci::session &sql = *wsv_impl.sql_;
        try {
          sql << "PREPARE TRANSACTION '" + prepared_block_name_ + "';";
          block_is_prepared = true;
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

    void StorageImpl::rollbackPrepared(soci::session &sql) {
      try {
        sql << "ROLLBACK PREPARED '" + prepared_block_name_ + "';";
        block_is_prepared = false;
      } catch (const std::exception &e) {
        log_->info("{}", formatPostgresMessage(e.what()));
      }
    }

    bool StorageImpl::storeBlock(
        std::shared_ptr<const shared_model::interface::Block> block) {
      auto json_result = converter_->serialize(*block);
      return json_result.match(
          [this, &block](const expected::Value<std::string> &v) {
            if (block_store_->add(block->height(), stringToBytes(v.value))) {
              notifier_.get_subscriber().on_next(block);
              return true;
            } else {
              log_->error("Block insertion failed: {}", *block);
              return false;
            }
          },
          [this, &block](const expected::Error<std::string> &e) {
            log_->error("Block serialization failed: {}: {}", *block, e.error);
            return false;
          });
    }

    const std::string &StorageImpl::drop_ = R"(
DROP TABLE IF EXISTS account_has_signatory;
DROP TABLE IF EXISTS account_has_asset;
DROP TABLE IF EXISTS role_has_permissions CASCADE;
DROP TABLE IF EXISTS account_has_roles;
DROP TABLE IF EXISTS account_has_grantable_permissions CASCADE;
DROP TABLE IF EXISTS account;
DROP TABLE IF EXISTS asset;
DROP TABLE IF EXISTS domain;
DROP TABLE IF EXISTS signatory;
DROP TABLE IF EXISTS peer;
DROP TABLE IF EXISTS role;
DROP TABLE IF EXISTS height_by_hash;
DROP INDEX IF EXISTS tx_status_by_hash_hash_index;
DROP TABLE IF EXISTS tx_status_by_hash;
DROP TABLE IF EXISTS height_by_account_set;
DROP TABLE IF EXISTS index_by_creator_height;
DROP TABLE IF EXISTS position_by_account_asset;
DROP TABLE IF EXISTS position_by_hash;
)";

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

    const std::string &StorageImpl::init_ =
        R"(
CREATE TABLE IF NOT EXISTS role (
    role_id character varying(32),
    PRIMARY KEY (role_id)
);
CREATE TABLE IF NOT EXISTS domain (
    domain_id character varying(255),
    default_role character varying(32) NOT NULL REFERENCES role(role_id),
    PRIMARY KEY (domain_id)
);
CREATE TABLE IF NOT EXISTS signatory (
    public_key varchar NOT NULL,
    PRIMARY KEY (public_key)
);
CREATE TABLE IF NOT EXISTS account (
    account_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    quorum int NOT NULL,
    data JSONB,
    PRIMARY KEY (account_id)
);
CREATE TABLE IF NOT EXISTS account_has_signatory (
    account_id character varying(288) NOT NULL REFERENCES account,
    public_key varchar NOT NULL REFERENCES signatory,
    PRIMARY KEY (account_id, public_key)
);
CREATE TABLE IF NOT EXISTS peer (
    public_key varchar NOT NULL,
    address character varying(261) NOT NULL UNIQUE,
    PRIMARY KEY (public_key)
);
CREATE TABLE IF NOT EXISTS asset (
    asset_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    precision int NOT NULL,
    data json,
    PRIMARY KEY (asset_id)
);
CREATE TABLE IF NOT EXISTS account_has_asset (
    account_id character varying(288) NOT NULL REFERENCES account,
    asset_id character varying(288) NOT NULL REFERENCES asset,
    amount decimal NOT NULL,
    PRIMARY KEY (account_id, asset_id)
);
CREATE TABLE IF NOT EXISTS role_has_permissions (
    role_id character varying(32) NOT NULL REFERENCES role,
    permission bit()"
        + std::to_string(shared_model::interface::RolePermissionSet::size())
        + R"() NOT NULL,
    PRIMARY KEY (role_id)
);
CREATE TABLE IF NOT EXISTS account_has_roles (
    account_id character varying(288) NOT NULL REFERENCES account,
    role_id character varying(32) NOT NULL REFERENCES role,
    PRIMARY KEY (account_id, role_id)
);
CREATE TABLE IF NOT EXISTS account_has_grantable_permissions (
    permittee_account_id character varying(288) NOT NULL REFERENCES account,
    account_id character varying(288) NOT NULL REFERENCES account,
    permission bit()"
        + std::to_string(
              shared_model::interface::GrantablePermissionSet::size())
        + R"() NOT NULL,
    PRIMARY KEY (permittee_account_id, account_id)
);
CREATE TABLE IF NOT EXISTS position_by_hash (
    hash varchar,
    height text,
    index text
);

CREATE TABLE IF NOT EXISTS tx_status_by_hash (
    hash varchar,
    status boolean
);
CREATE INDEX IF NOT EXISTS tx_status_by_hash_hash_index ON tx_status_by_hash USING hash (hash);

CREATE TABLE IF NOT EXISTS height_by_account_set (
    account_id text,
    height text
);
CREATE TABLE IF NOT EXISTS index_by_creator_height (
    id serial,
    creator_id text,
    height text,
    index text
);
CREATE TABLE IF NOT EXISTS position_by_account_asset (
    account_id text,
    asset_id text,
    height text,
    index text
);
)";
    }  // namespace ametsuchi
}  // namespace iroha
