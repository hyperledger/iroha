/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/impl/pg_connection_init.hpp"

#include "logger/logger.hpp"

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
    ReconnectionStrategyFactory &reconnection_strategy_factory,
    const PostgresOptions &options,
    logger::LoggerManagerTreePtr log_manager) {
  const int pool_size = 10;

  auto options_str = options.optionsString();

  auto conn = initPostgresConnection(options_str, pool_size);
  if (auto e = boost::get<expected::Error<std::string>>(&conn)) {
    return expected::makeError(std::move(e->error));
  }

  auto &connection =
      boost::get<expected::Value<std::shared_ptr<soci::connection_pool>>>(conn)
          .value;

  soci::session sql(*connection);
  bool enable_prepared_transactions = preparedTransactionsAvailable(sql);
  try {
    std::string prepared_block_name = "prepared_block" + options.dbname();

    auto try_rollback = [&](soci::session &session) {
      if (enable_prepared_transactions) {
        rollbackPrepared(session, prepared_block_name)
            .match([](auto &&v) {},
                   [&](auto &&e) {
                     log_manager->getLogger()->warn(
                         "rollback on creation has failed: {}", e.error);
                   });
      }
    };

    std::unique_ptr<FailoverCallbackFactory> failover_callback_factory =
        std::make_unique<FailoverCallbackFactory>();

    initializeConnectionPool(*connection,
                             pool_size,
                             init_,
                             try_rollback,
                             *failover_callback_factory,
                             reconnection_strategy_factory,
                             options.optionsStringWithoutDbName(),
                             log_manager);

    return expected::makeValue<std::shared_ptr<PoolWrapper>>(
        std::make_shared<iroha::ametsuchi::PoolWrapper>(
            std::move(connection),
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
PgConnectionInit::createDatabaseIfNotExist(
    const std::string &dbname, const std::string &options_str_without_dbname) {
  try {
    soci::session sql(*soci::factory_postgresql(), options_str_without_dbname);

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

const std::string PgConnectionInit::kDefaultDatabaseName{"iroha_default"};

const std::string PgConnectionInit::init_ = R"(
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
    + std::to_string(shared_model::interface::GrantablePermissionSet::size())
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
