/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/pg_connection_init.hpp"

#include <boost/functional/hash.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include "common/irohad_version.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

using namespace iroha::ametsuchi;

namespace {
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

  iroha::expected::Result<void, std::string> dropDatabaseIfExists(
      soci::session &maintenance_sql, const std::string &db_name) {
    try {
      size_t count;
      maintenance_sql
          << "SELECT count(datname) FROM pg_catalog.pg_database WHERE "
             "datname = :db_name",
          soci::into(count), soci::use(db_name, "db_name");

      if (count == 1) {
        maintenance_sql << "DROP DATABASE " + db_name;
      }
    } catch (std::exception &e) {
      return fmt::format(
          "Dropping database '{}' failed: {}", db_name, e.what());
    }
    return iroha::expected::Value<void>();
  }
}  // namespace

iroha::expected::Result<std::shared_ptr<soci::connection_pool>, std::string>
PgConnectionInit::initPostgresConnection(std::string &options_str,
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

iroha::expected::Result<void, std::string>
PgConnectionInit::prepareWorkingDatabase(const bool keep_wsv_data,
                                         const PostgresOptions &options) {
  return getMaintenanceSession(options) | [&](auto maintenance_sql) {
    if (keep_wsv_data) {
      return isSchemaCompatible(options) | [&](bool is_compatible)
                 -> iroha::expected::Result<void, std::string> {
        if (not is_compatible) {
          return "The schema is not compatible. "
                 "Either overwrite the ledger or use a compatible binary "
                 "version.";
        }
        return iroha::expected::Value<void>{};
      };
    }
    return dropSchema(options) | [&] { return createSchema(options); };
  };
}

iroha::expected::Result<PoolWrapper, std::string>
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
                                    options.maintenanceConnectionString(),
                                    log_manager)
               | [&]() -> iroha::expected::Result<PoolWrapper, std::string> {
      return iroha::ametsuchi::PoolWrapper{std::move(connection),
                                           std::move(failover_callback_factory),
                                           enable_prepared_transactions};
    };

  } catch (const std::exception &e) {
    return expected::makeError(e.what());
  }
}

bool PgConnectionInit::preparedTransactionsAvailable(soci::session &sql) {
  int prepared_txs_count = 0;
  try {
    sql << "SHOW max_prepared_transactions;", soci::into(prepared_txs_count);
    return prepared_txs_count != 0;
  } catch (std::exception &e) {
    return false;
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

template <typename RollbackFunction>
iroha::expected::Result<void, std::string>
PgConnectionInit::initializeConnectionPool(
    soci::connection_pool &connection_pool,
    size_t pool_size,
    RollbackFunction try_rollback,
    FailoverCallbackHolder &callback_factory,
    const ReconnectionStrategyFactory &reconnection_strategy_factory,
    const std::string &pg_reconnection_options,
    logger::LoggerManagerTreePtr log_manager) {
  auto log = log_manager->getLogger();
  auto initialize_session = [&](soci::session &session,
                                auto on_init_db,
                                auto on_init_connection) {
    auto *backend =
        static_cast<soci::postgresql_session_backend *>(session.get_backend());
    PQsetNoticeProcessor(backend->conn_, &processPqNotice, log.get());
    on_init_connection(session);

    // TODO: 2019-05-06 @muratovv rework unhandled exception with Result
    // IR-464
    on_init_db(session);
    PostgresCommandExecutor::prepareStatements(session);
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
            ->getChild("SOCI connection " + std::to_string(connection_index++))
            ->getLogger());

    session.set_failover_callback(callback);
  };

  assert(pool_size > 0);

  initialize_session(connection_pool.at(0), init_db, init_failover_callback);
  for (size_t i = 1; i != pool_size; i++) {
    soci::session &session = connection_pool.at(i);
    initialize_session(session, [](auto &) {}, init_failover_callback);
  }
  return expected::Value<void>();
}

const std::string PgConnectionInit::prepare_database_sql_ =
    "create database {};";

const std::string PgConnectionInit::prepare_tables_sql_ = R"(
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
    PRIMARY KEY (public_key)
);
CREATE TABLE asset (
    asset_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    precision int NOT NULL,
    data json,
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
    + std::to_string(shared_model::interface::GrantablePermissionSet::size())
    + R"() NOT NULL,
    PRIMARY KEY (permittee_account_id, account_id)
);
CREATE TABLE position_by_hash (
    hash varchar,
    height bigint,
    index bigint
);

CREATE TABLE tx_status_by_hash (
    hash varchar,
    status boolean
);
CREATE INDEX tx_status_by_hash_hash_index ON tx_status_by_hash USING hash (hash);

CREATE TABLE height_by_account_set (
    account_id text,
    height bigint
);
CREATE TABLE index_by_creator_height (
    id serial,
    creator_id text,
    height bigint,
    index bigint
);
CREATE TABLE position_by_account_asset (
    account_id text,
    asset_id text,
    height bigint,
    index bigint
);
)";

iroha::expected::Result<void, std::string> PgConnectionInit::createSchema(
    const PostgresOptions &postgres_options) {
  try {
    return getMaintenanceSession(postgres_options) | [&](auto maintenance_sql) {
      *maintenance_sql << fmt::format(prepare_database_sql_,
                                      postgres_options.workingDbName());
      return getWorkingDbSession(postgres_options) | [](auto session)
                 -> iroha::expected::Result<void, std::string> {
        *session << prepare_tables_sql_;
        return iroha::expected::Value<void>{};
      };
    };
  } catch (const std::exception &e) {
    return e.what();
  }
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

iroha::expected::Result<void, std::string> PgConnectionInit::dropSchema(
    const PostgresOptions &postgres_options) {
  return getMaintenanceSession(postgres_options) | [&](auto maintenance_sql)
             -> iroha::expected::Result<void, std::string> {
    return dropDatabaseIfExists(*maintenance_sql,
                                postgres_options.workingDbName());
  };
}
