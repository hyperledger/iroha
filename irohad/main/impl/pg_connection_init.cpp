/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/pg_connection_init.hpp"

#include <boost/functional/hash.hpp>
#include <boost/range/adaptor/transformed.hpp>

#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "common/irohad_version.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

using namespace iroha::ametsuchi;

namespace {
  /// Database connection pool size. Limits the number of similtaneous accesses.
  constexpr int kDbPoolSize = 10;

  /// Prototypes
  void prepareTables(soci::session &session);
  bool preparedTransactionsAvailable(soci::session &sql);
  iroha::expected::Result<void, std::string> createSchema(
      const PostgresOptions &postgres_options);
  /**
   * Function initializes existing connection pool
   * @param connection_pool - pool with connections
   * @param pool_size - number of connections in pool
   * @param try_rollback - function which performs blocks rollback before
   * initialization
   * @param callback_factory - factory for reconnect callbacks
   * @param reconnection_strategy_factory - factory which creates strategies
   * for each connection
   * @param pg_reconnection_options - parameter of connection startup on
   * reconnect
   * @param log_manager - log manager of storage
   * @tparam RollbackFunction - type of rollback function
   * @return void value on success or string error
   */
  template <typename RollbackFunction>
  iroha::expected::Result<void, std::string> initializeConnectionPool(
      soci::connection_pool &connection_pool,
      size_t pool_size,
      RollbackFunction try_rollback,
      FailoverCallbackHolder &callback_factory,
      const ReconnectionStrategyFactory &reconnection_strategy_factory,
      const std::string &pg_reconnection_options,
      logger::LoggerManagerTreePtr log_manager);

  std::string formatPostgresMessage(const char *message) {
    std::string formatted_message(message);
    boost::replace_if(formatted_message, boost::is_any_of("\r\n"), ' ');
    return formatted_message;
  }

  /// WSV schema version is identified by compatibile irohad version.
  using SchemaVersion = iroha::IrohadVersion;

  /**
   * Get the version of database.
   * @param sql a connection to working database
   * @return result of schema version or error.
   */
  iroha::expected::Result<SchemaVersion, std::string> getDbSchemaVersion(
      soci::session &sql) {
    SchemaVersion version;
    try {
      int test = 0;
      sql << "select "
             "1 test, iroha_major, iroha_minor, iroha_patch "
             "from schema_version;",
          soci::into(test), soci::into(version.major),
          soci::into(version.minor), soci::into(version.patch);
      if (test == 0) {
        return "Database contains no schema version information.";
      }
    } catch (std::exception &e) {
      return iroha::expected::makeError(formatPostgresMessage(e.what()));
    }
    return version;
  }

  iroha::expected::Result<std::unique_ptr<soci::session>, std::string>
  getMaintenanceSession(const PostgresOptions &postgres_options) {
    try {
      return std::make_unique<soci::session>(
          *soci::factory_postgresql(),
          postgres_options.maintenanceConnectionString());
    } catch (std::exception &e) {
      return fmt::format("Could not connect to maintenance database: {}",
                         e.what());
    }
  };

  iroha::expected::Result<std::unique_ptr<soci::session>, std::string>
  getWorkingDbSession(const PostgresOptions &postgres_options) {
    try {
      return std::make_unique<soci::session>(
          *soci::factory_postgresql(),
          postgres_options.workingConnectionString());
    } catch (std::exception &e) {
      return fmt::format("Could not connect to working database '{}': {}",
                         postgres_options.workingDbName(),
                         e.what());
    }
  };

  /**
   * Checks schema compatibility.
   * @return value of true if the schema in the provided sql connection is
   * compatibile with this code, false if not and an error message if the
   * check could not be performed.
   */
  iroha::expected::Result<bool, std::string> isSchemaCompatible(
      const PostgresOptions &postgres_options) {
    return getWorkingDbSession(postgres_options) | [](auto sql) {
      return getDbSchemaVersion(*sql) |
          [](const SchemaVersion &db_schema_version) {
            return db_schema_version == iroha::getIrohadVersion();
          };
    };
  }

  void processPqNotice(void *arg, const char *message) {
    auto *log = reinterpret_cast<logger::Logger *>(arg);
    log->debug("{}", formatPostgresMessage(message));
  }

  iroha::expected::Result<std::shared_ptr<soci::connection_pool>, std::string>
  initPostgresConnection(std::string &options_str, size_t pool_size) {
    auto pool = std::make_shared<soci::connection_pool>(pool_size);

    try {
      for (size_t i = 0; i != pool_size; i++) {
        soci::session &session = pool->at(i);
        session.open(*soci::factory_postgresql(), options_str);
      }
    } catch (const std::exception &e) {
      return iroha::expected::makeError(formatPostgresMessage(e.what()));
    }
    return iroha::expected::makeValue(pool);
  }

  template <typename RollbackFunction>
  iroha::expected::Result<void, std::string> initializeConnectionPool(
      soci::connection_pool &connection_pool,
      size_t pool_size,
      RollbackFunction try_rollback,
      FailoverCallbackHolder &callback_factory,
      const ReconnectionStrategyFactory &reconnection_strategy_factory,
      const std::string &pg_reconnection_options,
      logger::LoggerManagerTreePtr log_manager) {
    auto log = log_manager->getLogger();
    auto initialize_session =
        [&](soci::session &session, auto on_init_db, auto on_init_connection) {
          auto *backend = static_cast<soci::postgresql_session_backend *>(
              session.get_backend());
          PQsetNoticeProcessor(backend->conn_, &processPqNotice, log.get());
          on_init_connection(session);

          // TODO: 2019-05-06 @muratovv rework unhandled exception with Result
          // IR-464
          on_init_db(session);
        };

    /// lambda contains special actions which should be execute once
    auto init_db = [&](soci::session &session) {
      // rollback current prepared transaction
      // if there exists any since last session
      try_rollback(session);
    };

    /// lambda contains actions which should be invoked once for each
    /// session
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

    initialize_session(connection_pool.at(0), init_db, init_failover_callback);
    for (size_t i = 1; i != pool_size; i++) {
      soci::session &session = connection_pool.at(i);
      initialize_session(session, [](auto &) {}, init_failover_callback);
    }
    return iroha::expected::Value<void>();
  }

  iroha::expected::Result<void, std::string> createSchema(
      const PostgresOptions &postgres_options) {
    try {
      return getMaintenanceSession(postgres_options) |
          [&](auto maintenance_sql) {
            *maintenance_sql << fmt::format("create database {};",
                                            postgres_options.workingDbName());
            return getWorkingDbSession(postgres_options) | [](auto session)
                       -> iroha::expected::Result<void, std::string> {
              prepareTables(*session);
              return iroha::expected::Value<void>{};
            };
          };
    } catch (const std::exception &e) {
      return e.what();
    }
  }

  bool preparedTransactionsAvailable(soci::session &sql) {
    int prepared_txs_count = 0;
    try {
      sql << "SHOW max_prepared_transactions;", soci::into(prepared_txs_count);
      return prepared_txs_count != 0;
    } catch (std::exception &e) {
      return false;
    }
  }

  void prepareTables(soci::session &session) {
    static const std::string prepare_tables_sql =
        R"(
CREATE TABLE schema_version (
    lock CHAR(1) DEFAULT 'X' NOT NULL PRIMARY KEY,
    iroha_major int not null,
    iroha_minor int not null,
    iroha_patch int not null
);
insert into schema_version
    (iroha_major, iroha_minor, iroha_patch)
    values ()"
        +
        [] {
          auto v = iroha::getIrohadVersion();
          return fmt::format("{}, {}, {}", v.major, v.minor, v.patch);
        }()
        + R"();
CREATE TABLE top_block_info (
    lock CHAR(1) DEFAULT 'X' NOT NULL PRIMARY KEY,
    height int,
    hash character varying(128)
);
CREATE TABLE role (
    role_id character varying(32),
    PRIMARY KEY (role_id)
);
CREATE TABLE domain (
    domain_id character varying(255),
    default_role character varying(32) NOT NULL REFERENCES role(role_id),
    PRIMARY KEY (domain_id)
);
CREATE TABLE signatory (
    public_key varchar NOT NULL,
    PRIMARY KEY (public_key)
);
CREATE TABLE account (
    account_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    quorum int NOT NULL,
    data JSONB,
    PRIMARY KEY (account_id)
);
CREATE TABLE account_has_signatory (
    account_id character varying(288) NOT NULL REFERENCES account,
    public_key varchar NOT NULL REFERENCES signatory,
    PRIMARY KEY (account_id, public_key)
);
CREATE TABLE peer (
    public_key varchar NOT NULL,
    address character varying(261) NOT NULL UNIQUE,
    tls_certificate varchar,
    PRIMARY KEY (public_key)
);
CREATE TABLE sync_peer (
    public_key varchar NOT NULL,
    address character varying(261) NOT NULL UNIQUE,
    tls_certificate varchar,
    PRIMARY KEY (public_key)
);
CREATE TABLE asset (
    asset_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    precision int NOT NULL,
    PRIMARY KEY (asset_id)
);
CREATE TABLE account_has_asset (
    account_id character varying(288) NOT NULL REFERENCES account,
    asset_id character varying(288) NOT NULL REFERENCES asset,
    amount decimal NOT NULL,
    PRIMARY KEY (account_id, asset_id)
);
CREATE TABLE role_has_permissions (
    role_id character varying(32) NOT NULL REFERENCES role,
    permission bit()"
        + std::to_string(shared_model::interface::RolePermissionSet::size())
        + R"() NOT NULL,
    PRIMARY KEY (role_id)
);
CREATE TABLE account_has_roles (
    account_id character varying(288) NOT NULL REFERENCES account,
    role_id character varying(32) NOT NULL REFERENCES role,
    PRIMARY KEY (account_id, role_id)
);
CREATE TABLE account_has_grantable_permissions (
    permittee_account_id character varying(288) NOT NULL REFERENCES account,
    account_id character varying(288) NOT NULL REFERENCES account,
    permission bit()"
        + std::to_string(
              shared_model::interface::GrantablePermissionSet::size())
        + R"() NOT NULL,
    PRIMARY KEY (permittee_account_id, account_id)
);
CREATE TABLE IF NOT EXISTS tx_positions (
    creator_id text,
    hash varchar(64) not null,
    asset_id text,
    ts bigint,
    height bigint,
    index bigint
);
CREATE INDEX IF NOT EXISTS tx_positions_hash_index
    ON tx_positions
    USING hash
    (hash);
CREATE INDEX IF NOT EXISTS tx_positions_creator_id_asset_index
    ON tx_positions
    (creator_id, asset_id);
CREATE INDEX IF NOT EXISTS tx_positions_ts_height_index_index
    ON tx_positions
    (ts);
CREATE TABLE IF NOT EXISTS tx_status_by_hash (
    hash varchar,
    status boolean
);
CREATE INDEX tx_status_by_hash_hash_index
  ON tx_status_by_hash
  USING hash
  (hash);
CREATE TABLE IF NOT EXISTS setting(
    setting_key text,
    setting_value text,
    PRIMARY KEY (setting_key)
);
CREATE TABLE IF NOT EXISTS engine_calls (
    call_id serial unique not null,
    tx_hash text,
    cmd_index bigint,
    engine_response text,
    callee varchar(40),
    created_address varchar(40),
    PRIMARY KEY (tx_hash, cmd_index)
);
CREATE TABLE IF NOT EXISTS burrow_account_data (
    address varchar(40),
    data text,
    PRIMARY KEY (address)
);
CREATE TABLE IF NOT EXISTS burrow_account_key_value (
    address varchar(40),
    key varchar(64),
    value text,
    PRIMARY KEY (address, key)
);
CREATE TABLE IF NOT EXISTS burrow_tx_logs (
    log_idx serial primary key,
    call_id integer references engine_calls(call_id),
    address varchar(40),
    data text
);
CREATE TABLE IF NOT EXISTS burrow_tx_logs_topics (
    topic varchar(64),
    log_idx integer references burrow_tx_logs(log_idx)
);
CREATE INDEX IF NOT EXISTS burrow_tx_logs_topics_log_idx
    ON burrow_tx_logs_topics
    USING btree
    (log_idx ASC);
)";
    session << prepare_tables_sql;
  }
}  // namespace

iroha::expected::Result<std::shared_ptr<iroha::ametsuchi::PoolWrapper>,
                        std::string>
PgConnectionInit::init(StartupWsvDataPolicy startup_wsv_data_policy,
                       iroha::ametsuchi::PostgresOptions const &pg_opt,
                       logger::LoggerManagerTreePtr log_manager,
                       bool skip_schema_check) {
  return prepareWorkingDatabase(
             startup_wsv_data_policy, pg_opt, skip_schema_check)
      | [&] {
          return prepareConnectionPool(KTimesReconnectionStrategyFactory{10},
                                       pg_opt,
                                       kDbPoolSize,
                                       log_manager);
        };
}

iroha::expected::Result<void, std::string>
PgConnectionInit::prepareWorkingDatabase(
    StartupWsvDataPolicy startup_wsv_data_policy,
    const PostgresOptions &options,
    bool skip_schema_check) {
  return getMaintenanceSession(options) | [&](auto maintenance_sql) {
    int work_db_exists;
    *maintenance_sql << "select exists("
                        "SELECT datname FROM pg_catalog.pg_database "
                        "WHERE datname = '"
            + options.workingDbName() + "');",
        soci::into(work_db_exists);
    if (not work_db_exists) {
      return createSchema(options);
    }
    if (startup_wsv_data_policy == StartupWsvDataPolicy::kDrop) {
      return dropWorkingDatabase(options) |
          [&] { return createSchema(options); };
    } else {  // StartupWsvDataPolicy::kReuse
      return isSchemaCompatible(options) | [&](bool is_compatible)
                 -> iroha::expected::Result<void, std::string> {
        if (not is_compatible && !skip_schema_check) {
          return "The schema is not compatible. "
                 "Either overwrite the ledger or use a compatible binary "
                 "version.";
        }
        return iroha::expected::Value<void>{};
      };
    }
  };
}

iroha::expected::Result<std::shared_ptr<PoolWrapper>, std::string>
PgConnectionInit::prepareConnectionPool(
    const ReconnectionStrategyFactory &reconnection_strategy_factory,
    const PostgresOptions &options,
    const int pool_size,
    logger::LoggerManagerTreePtr log_manager) {
  auto options_str = options.workingConnectionString();

  auto conn = initPostgresConnection(options_str, pool_size);
  if (auto e = boost::get<expected::Error<std::string>>(&conn)) {
    return *e;
  }

  auto &connection =
      boost::get<expected::Value<std::shared_ptr<soci::connection_pool>>>(conn)
          .value;

  soci::session sql(*connection);
  bool enable_prepared_transactions = preparedTransactionsAvailable(sql);
  try {
    auto try_rollback = [&](soci::session &session) {
      if (enable_prepared_transactions) {
        rollbackPrepared(session, options.preparedBlockName())
            .match([](auto &&v) {},
                   [&](auto &&e) {
                     log_manager->getLogger()->warn(
                         "rollback on creation has failed: {}", e.error);
                   });
      }
    };

    std::unique_ptr<FailoverCallbackHolder> failover_callback_factory =
        std::make_unique<FailoverCallbackHolder>();

    return initializeConnectionPool(*connection,
                                    pool_size,
                                    try_rollback,
                                    *failover_callback_factory,
                                    reconnection_strategy_factory,
                                    options_str,
                                    log_manager)
               | [&]() -> iroha::expected::Result<std::shared_ptr<PoolWrapper>,
                                                  std::string> {
      return std::make_shared<iroha::ametsuchi::PoolWrapper>(
          std::move(connection),
          std::move(failover_callback_factory),
          enable_prepared_transactions);
    };

  } catch (const std::exception &e) {
    return expected::makeError(e.what());
  }
}

iroha::expected::Result<void, std::string> PgConnectionInit::rollbackPrepared(
    soci::session &sql, const std::string &prepared_block_name) {
  try {
    sql << "ROLLBACK PREPARED '" + prepared_block_name + "';";
  } catch (const std::exception &e) {
    return iroha::expected::makeError(formatPostgresMessage(e.what()));
  }
  return {};
}

iroha::expected::Result<void, std::string>
PgConnectionInit::dropWorkingDatabase(const PostgresOptions &options) try {
  auto maintenance_sql = soci::session(*soci::factory_postgresql(),
                                       options.maintenanceConnectionString());
  maintenance_sql << "DROP DATABASE IF EXISTS " << options.workingDbName()
                  << ";";
  return iroha::expected::Value<void>{};
} catch (const std::exception &e) {
  return e.what();
}

iroha::expected::Result<void, std::string> PgConnectionInit::resetPeers(
    soci::session &sql) {
  try {
    static const std::string reset_peers = R"(
      TRUNCATE TABLE peer RESTART IDENTITY CASCADE;
    )";
    sql << reset_peers;
  } catch (std::exception &e) {
    return iroha::expected::makeError(std::string{"Failed to reset peers: "}
                                      + formatPostgresMessage(e.what()));
  }
  return expected::Value<void>();
}
