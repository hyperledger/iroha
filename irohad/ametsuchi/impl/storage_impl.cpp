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
#include "backend/protobuf/permissions.hpp"
#include "common/bind.hpp"
#include "common/byteutils.hpp"
#include "converters/protobuf/json_proto_converter.hpp"
#include "cryptography/public_key.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace {

  static const std::string kDefaultDatabaseName{"iroha_default"};

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

  iroha::expected::Result<void, std::string> rollbackPrepared(
      soci::session &sql, const std::string &prepared_block_name) {
    try {
      sql << "ROLLBACK PREPARED '" + prepared_block_name + "';";
    } catch (const std::exception &e) {
      return iroha::expected::makeError(formatPostgresMessage(e.what()));
    }
    return {};
  }

}  // namespace

namespace iroha {
  namespace ametsuchi {

    /**
     * Class provides reconnection callback for postgresql session
     * Note: the class is a workaround for SOCI 4.0, support in future versions
     * is not guaranteed
     */
    class FailoverCallback : public soci::failover_callback {
     public:
      using InitFunctionType = std::function<void(soci::session &)>;
      FailoverCallback(
          soci::session &connection,
          InitFunctionType init,
          std::string connection_options,
          std::unique_ptr<ReconnectionStrategy> reconnection_strategy,
          logger::LoggerPtr log)
          : connection_(connection),
            init_session_(std::move(init)),
            connection_options_(std::move(connection_options)),
            reconnection_strategy_(std::move(reconnection_strategy)),
            log_(std::move(log)) {}

      FailoverCallback(const FailoverCallback &) = delete;
      FailoverCallback &operator=(const FailoverCallback &) = delete;

      virtual void started() {
        reconnection_strategy_->reset();
        log_->debug("Reconnection process is initiated");
      }

      virtual void finished(soci::session &) {}

      virtual void failed(bool &should_reconnect, std::string &) {
        // don't rely on reconnection in soci because we are going to conduct
        // our own reconnection process
        should_reconnect = false;
        log_->warn(
            "failed to connect to the database. The system will try to "
            "reconnect");
        auto is_reconnected = reconnectionLoop();
        log_->info("re-established: {}", is_reconnected);
      }

      virtual void aborted() {
        log_->error("has invoked aborted method of FailoverCallback");
      }

     private:
      bool reconnectionLoop() {
        bool successful_reconnection = false;
        while (reconnection_strategy_->canReconnect()
               and not successful_reconnection) {
          try {
            soci::connection_parameters parameters(*soci::factory_postgresql(),
                                                   connection_options_);
            auto *pg_connection =
                static_cast<soci::postgresql_session_backend *>(
                    connection_.get_backend());
            auto &conn_ = pg_connection->conn_;

            auto clean_up = [](auto &conn_) {
              if (0 != conn_) {
                PQfinish(conn_);
                conn_ = 0;
              }
            };

            auto check_for_data = [](auto &conn, auto *result, auto *errMsg) {
              std::string msg(errMsg);

              ExecStatusType const status = PQresultStatus(result);
              switch (status) {
                case PGRES_EMPTY_QUERY:
                case PGRES_COMMAND_OK:
                  // No data but don't throw neither.
                  return false;

                case PGRES_TUPLES_OK:
                  return true;

                case PGRES_FATAL_ERROR:
                  msg += " Fatal error.";

                  if (PQstatus(conn) == CONNECTION_BAD) {
                    msg += " Connection failed.";
                  }

                  break;

                default:
                  // Some of the other status codes are not really errors
                  // but we're not prepared to handle them right now and
                  // shouldn't ever receive them so throw nevertheless

                  break;
              }

              const char *const pqError = PQresultErrorMessage(result);
              if (pqError && *pqError) {
                msg += " ";
                msg += pqError;
              }

              const char *sqlstate =
                  PQresultErrorField(result, PG_DIAG_SQLSTATE);
              const char *const blank_sql_state = "     ";
              if (!sqlstate) {
                sqlstate = blank_sql_state;
              }

              throw std::runtime_error(msg);
            };

            auto connect = [check_for_data](auto &conn, auto &parameters) {
              PGconn *new_conn =
                  PQconnectdb(parameters.get_connect_string().c_str());
              if (0 == new_conn || CONNECTION_OK != PQstatus(new_conn)) {
                std::string msg =
                    "Cannot establish connection to the database.";
                if (0 != new_conn) {
                  msg += '\n';
                  msg += PQerrorMessage(new_conn);
                  PQfinish(new_conn);
                }

                throw std::runtime_error(msg);
              }

              // Increase the number of digits used for floating point values to
              // ensure that the conversions to/from text round trip correctly,
              // which is not the case with the default value of 0. Use the
              // maximal supported value, which was 2 until 9.x and is 3 since
              // it.
              int const version = PQserverVersion(new_conn);
              check_for_data(
                  new_conn,
                  PQexec(new_conn,
                         version >= 90000 ? "SET extra_float_digits = 3"
                                          : "SET extra_float_digits = 2"),
                  "Cannot set extra_float_digits parameter");

              conn = new_conn;
            };

            clean_up(conn_);
            connect(conn_, parameters);

            init_session_(connection_);
            successful_reconnection = true;
          } catch (const std::exception &e) {
            log_->warn("attempt to reconnect has failed: {}", e.what());
          }
        }
        return successful_reconnection;
      }

      soci::session &connection_;
      InitFunctionType init_session_;
      const std::string connection_options_;
      std::unique_ptr<ReconnectionStrategy> reconnection_strategy_;
      logger::LoggerPtr log_;
    };

    class FailoverCallbackFactory {
     public:
      FailoverCallback &makeFailoverCallback(
          soci::session &connection,
          FailoverCallback::InitFunctionType init,
          std::string connection_options,
          std::unique_ptr<ReconnectionStrategy> reconnection_strategy,
          logger::LoggerPtr log) {
        callbacks_.push_back(
            std::make_unique<FailoverCallback>(connection,
                                               std::move(init),
                                               std::move(connection_options),
                                               std::move(reconnection_strategy),
                                               std::move(log)));
        return *callbacks_.back();
      }

     private:
      std::vector<std::unique_ptr<FailoverCallback>> callbacks_;
    };

    StorageImpl::PoolWrapper::PoolWrapper(
        std::shared_ptr<soci::connection_pool> connection_pool,
        std::unique_ptr<FailoverCallbackFactory> failover_callback_factory)
        : connection_pool_(std::move(connection_pool)),
          failover_callback_factory_(std::move(failover_callback_factory)) {}

    const char *kCommandExecutorError = "Cannot create CommandExecutorFactory";
    const char *kPsqlBroken = "Connection to PostgreSQL broken: %s";
    const char *kTmpWsv = "TemporaryWsv";

    ConnectionContext::ConnectionContext(
        std::unique_ptr<KeyValueStorage> block_store)
        : block_store(std::move(block_store)) {}

    StorageImpl::StorageImpl(
        PostgresOptions postgres_options,
        std::unique_ptr<KeyValueStorage> block_store,
        PoolWrapper pool_wrapper,
        std::shared_ptr<shared_model::interface::CommonObjectsFactory> factory,
        std::shared_ptr<shared_model::interface::BlockJsonConverter> converter,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::unique_ptr<BlockStorageFactory> block_storage_factory,
        size_t pool_size,
        bool enable_prepared_blocks,
        const std::string &prepared_block_name,
        logger::LoggerManagerTreePtr log_manager)
        : postgres_options_(std::move(postgres_options)),
          block_store_(std::move(block_store)),
          pool_wrapper_(std::move(pool_wrapper)),
          connection_(pool_wrapper_.connection_pool_),
          factory_(std::move(factory)),
          notifier_(notifier_lifetime_),
          converter_(std::move(converter)),
          perm_converter_(std::move(perm_converter)),
          block_storage_factory_(std::move(block_storage_factory)),
          log_manager_(std::move(log_manager)),
          log_(log_manager_->getLogger()),
          pool_size_(pool_size),
          prepared_blocks_enabled_(enable_prepared_blocks),
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
              std::make_shared<PostgresCommandExecutor>(*sql, perm_converter_),
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

    /**
     * Function initializes existing connection pool
     * @param connection_pool - pool with connections
     * @param pool_size - number of connections in pool
     * @param prepare_tables_sql - sql code for db initialization
     * @param try_rollback - function which performs blocks rollback before
     * initialization
     * @param callback_factory - factory for reconnect callbacks
     * @param reconnection_strategy_factory - factory which creates strategies
     * for each connection
     * @param pg_reconnection_options - parameter of connection startup on
     * reconnect
     * @param log_manager - log manager of storage
     * @tparam RollbackFunction - type of rollback function
     */
    template <typename RollbackFunction>
    void initializeConnectionPool(
        soci::connection_pool &connection_pool,
        size_t pool_size,
        const std::string &prepare_tables_sql,
        RollbackFunction try_rollback,
        FailoverCallbackFactory &callback_factory,
        ReconnectionStrategyFactory &reconnection_strategy_factory,
        const std::string &pg_reconnection_options,
        logger::LoggerManagerTreePtr log_manager) {
      auto log = log_manager->getLogger();
      auto initialize_session = [&](soci::session &session,
                                    auto on_init_db,
                                    auto on_init_connection) {
        auto *backend = static_cast<soci::postgresql_session_backend *>(
            session.get_backend());
        PQsetNoticeProcessor(backend->conn_, &processPqNotice, log.get());
        on_init_connection(session);

        // TODO: 2019-05-06 @muratovv rework unhandled exception with Result
        // IR-464
        on_init_db(session);
        iroha::ametsuchi::PostgresCommandExecutor::prepareStatements(session);
      };

      /// lambda contains special actions which should be execute once
      auto init_db = [&](soci::session &session) {
        // rollback current prepared transaction
        // if there exists any since last session
        try_rollback(session);
        session << prepare_tables_sql;
      };

      /// lambda contains actions which should be invoked once for each session
      auto init_failover_callback = [&](soci::session &session) {
        static size_t connection_index = 0;
        auto restore_session = [initialize_session](soci::session &s) {
          return initialize_session(s, [](auto &) {}, [](auto &) {});
        };

        auto &callback = callback_factory.makeFailoverCallback(
            session,
            restore_session,
            pg_reconnection_options,
            reconnection_strategy_factory.create(),
            log_manager
                ->getChild("SOCI connection "
                           + std::to_string(connection_index++))
                ->getLogger());

        session.set_failover_callback(callback);
      };

      assert(pool_size > 0);

      initialize_session(
          connection_pool.at(0), init_db, init_failover_callback);
      for (size_t i = 1; i != pool_size; i++) {
        soci::session &session = connection_pool.at(i);
        initialize_session(session, [](auto &) {}, init_failover_callback);
      }
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
        std::unique_ptr<ReconnectionStrategyFactory>
            reconnection_strategy_factory,
        logger::LoggerManagerTreePtr log_manager,
        size_t pool_size) {
      boost::optional<std::string> string_res = boost::none;

      PostgresOptions options(
          postgres_options,
          kDefaultDatabaseName,
          log_manager->getChild("DbOptionsParser")->getLogger());

      // create database if it does not exist
      createDatabaseIfNotExist(options.dbname(),
                               options.optionsStringWithoutDbName())
          .match([](auto &&val) {},
                 [&string_res](auto &&error) { string_res = error.error; });

      if (string_res) {
        return expected::makeError(string_res.value());
      }

      auto ctx_result =
          initConnections(block_store_dir, log_manager->getLogger());
      auto db_result = initPostgresConnection(postgres_options, pool_size);
      expected::Result<std::shared_ptr<StorageImpl>, std::string> storage;
      std::move(ctx_result)
          .match(
              [&](auto &&ctx) {
                std::move(db_result).match(
                    [&](auto &&connection) {
                      soci::session sql(*connection.value);
                      bool enable_prepared_transactions =
                          preparedTransactionsAvailable(sql);
                      try {
                        std::string prepared_block_name =
                            "prepared_block" + options.dbname();

                        auto try_rollback = [&prepared_block_name,
                                             &enable_prepared_transactions,
                                             &log_manager](
                                                soci::session &session) {
                          if (enable_prepared_transactions) {
                            rollbackPrepared(session, prepared_block_name)
                                .match(
                                    [](auto &&v) {},
                                    [log = log_manager->getLogger()](auto &&e) {
                                      log->warn(
                                          "rollback on creation has failed: {}",
                                          std::move(e.error));
                                    });
                          }
                        };

                        std::unique_ptr<FailoverCallbackFactory>
                            failover_callback_factory =
                                std::make_unique<FailoverCallbackFactory>();

                        initializeConnectionPool(
                            *connection.value,
                            pool_size,
                            init_,
                            try_rollback,
                            *failover_callback_factory,
                            *reconnection_strategy_factory,
                            options.optionsStringWithoutDbName(),
                            log_manager);

                        PoolWrapper pool_wrapper(
                            std::move(connection.value),
                            std::move(failover_callback_factory));

                        storage = expected::makeValue(
                            std::shared_ptr<StorageImpl>(new StorageImpl(
                                options,
                                std::move(ctx.value.block_store),
                                std::move(pool_wrapper),
                                factory,
                                converter,
                                perm_converter,
                                std::move(block_storage_factory),
                                pool_size,
                                enable_prepared_transactions,
                                prepared_block_name,
                                std::move(log_manager))));
                      } catch (const std::exception &e) {
                        storage = expected::makeError(e.what());
                      }
                    },
                    [&](const auto &error) { storage = error; });
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
                   | [this, &block, &sql](auto &&peers)
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
      if (block_is_prepared_) {
        rollbackPrepared(session, prepared_block_name_)
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
    height bigint,
    index bigint
);

CREATE TABLE IF NOT EXISTS tx_status_by_hash (
    hash varchar,
    status boolean
);
CREATE INDEX IF NOT EXISTS tx_status_by_hash_hash_index ON tx_status_by_hash USING hash (hash);

CREATE TABLE IF NOT EXISTS height_by_account_set (
    account_id text,
    height bigint
);
CREATE TABLE IF NOT EXISTS index_by_creator_height (
    id serial,
    creator_id text,
    height bigint,
    index bigint
);
CREATE TABLE IF NOT EXISTS position_by_account_asset (
    account_id text,
    asset_id text,
    height bigint,
    index bigint
);
)";
  }  // namespace ametsuchi
}  // namespace iroha
