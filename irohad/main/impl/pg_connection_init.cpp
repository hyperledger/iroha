/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/pg_connection_init.hpp"

#include "ametsuchi/impl/pool_wrapper.hpp"
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

namespace {
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

using namespace iroha::ametsuchi;

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

    initializeConnectionPool(*connection,
                             pool_size,
                             try_rollback,
                             *failover_callback_factory,
                             reconnection_strategy_factory,
                             options.maintenanceConnectionString(),
                             log_manager);

    return expected::makeValue<std::shared_ptr<PoolWrapper>>(
        std::make_shared<PoolWrapper>(std::move(connection),
                                      std::move(failover_callback_factory),
                                      enable_prepared_transactions));

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

iroha::expected::Result<bool, std::string>
PgConnectionInit::checkIfWorkingDatabaseExists(const PostgresOptions &pg_opt) {
  try {
    soci::session sql(*soci::factory_postgresql(),
                      pg_opt.maintenanceConnectionString());

    size_t count;
    std::string working_dbname = pg_opt.workingDbName();

    sql << "SELECT count(datname) FROM pg_catalog.pg_database WHERE "
           "datname = :dbname",
        soci::into(count), soci::use(working_dbname, "dbname");

    return expected::makeValue(count == 1);
  } catch (std::exception &e) {
    return expected::makeError<std::string>(
        std::string("Connection to PostgreSQL broken: ")
        + formatPostgresMessage(e.what()));
  }
}

iroha::expected::Result<bool, std::string>
PgConnectionInit::createDatabaseIfNotExist(const PostgresOptions &pg_opt) {
  return checkIfWorkingDatabaseExists(pg_opt) |
             [&pg_opt](
                 bool db_exists) -> iroha::expected::Result<bool, std::string> {
    try {
      if (not db_exists) {
        soci::session sql(*soci::factory_postgresql(),
                          pg_opt.maintenanceConnectionString());
        sql << "CREATE DATABASE " + pg_opt.workingDbName();
        return expected::makeValue(true);
      }
      return expected::makeValue(false);
    } catch (std::exception &e) {
      return expected::makeError<std::string>(
          std::string("Connection to PostgreSQL broken: ")
          + formatPostgresMessage(e.what()));
    }
  };
}

template <typename RollbackFunction>
void PgConnectionInit::initializeConnectionPool(
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
  };

  /// lambda contains special actions which should be execute once
  auto init_db = [&](soci::session &session) {
    // rollback current prepared transaction
    // if there exists any since last session
    try_rollback(session);
    prepareTables(session);
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
}

void PgConnectionInit::prepareTables(soci::session &session) {
  static const std::string prepare_tables_sql = R"(
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
    tls_certificate varchar,
    PRIMARY KEY (public_key)
);
CREATE TABLE IF NOT EXISTS asset (
    asset_id character varying(288),
    domain_id character varying(255) NOT NULL REFERENCES domain,
    precision int NOT NULL,
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
      + std::to_string(shared_model::interface::GrantablePermissionSet::size())
      + R"() NOT NULL,
    PRIMARY KEY (permittee_account_id, account_id)
);
CREATE TABLE IF NOT EXISTS position_by_hash (
    hash varchar unique not null,
    height bigint,
    index bigint
);
CREATE INDEX IF NOT EXISTS position_by_hash_hash_index
    ON position_by_hash
    USING hash
    (hash);
CREATE TABLE IF NOT EXISTS tx_status_by_hash (
    hash varchar,
    status boolean
);
CREATE INDEX IF NOT EXISTS tx_status_by_hash_hash_index
  ON tx_status_by_hash
  USING hash
  (hash);
CREATE TABLE IF NOT EXISTS tx_position_by_creator (
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
CREATE INDEX IF NOT EXISTS position_by_account_asset_index
    ON position_by_account_asset
    USING btree
    (account_id, asset_id, height, index ASC);
CREATE TABLE IF NOT EXISTS setting(
    setting_key text,
    setting_value text,
    PRIMARY KEY (setting_key)
);)";

  session << prepare_tables_sql;
}

iroha::expected::Result<void, std::string> PgConnectionInit::resetWsv(
    soci::session &sql) {
  try {
    static const std::string reset = R"(
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
      TRUNCATE TABLE tx_position_by_creator RESTART IDENTITY CASCADE;
      TRUNCATE TABLE position_by_account_asset RESTART IDENTITY CASCADE;
      TRUNCATE TABLE setting RESTART IDENTITY CASCADE;
    )";
    sql << reset;
  } catch (std::exception &e) {
    return iroha::expected::makeError(std::string{"Failed to reset WSV: "}
                                      + formatPostgresMessage(e.what()));
  }
  return expected::Value<void>();
}

iroha::expected::Result<void, std::string>
PgConnectionInit::dropWorkingDatabase(const PostgresOptions &options) {
  soci::session sql(*soci::factory_postgresql(),
                    options.maintenanceConnectionString());
  try {
    sql << "DROP DATABASE " + options.workingDbName();
  } catch (std::exception &e) {
    return iroha::expected::makeError(
        std::string{"Failed to drop working database: "}
        + formatPostgresMessage(e.what()));
  }
  return expected::Value<void>();
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
