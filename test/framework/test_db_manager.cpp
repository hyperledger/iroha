/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/test_db_manager.hpp"

#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "framework/config_helper.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "logger/logger_manager.hpp"
#include "main/impl/pg_connection_init.hpp"
#include "main/startup_params.hpp"

using namespace framework::expected;
using namespace integration_framework;
using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::integration_framework;

static constexpr size_t kMaxCreateDbAttempts = 8;
static constexpr size_t kMaxReconnectionAttempts = 8;

/// Drops a database on destruction.
class TestDbManager::DbDropper {
 public:
  DbDropper(std::unique_ptr<soci::session> management_session,
            std::string dropped_db_name)
      : management_session_(std::move(management_session)),
        dropped_db_name_(std::move(dropped_db_name)) {}
  ~DbDropper() {
    *management_session_ << "DROP DATABASE " + dropped_db_name_;
  }

 private:
  std::unique_ptr<soci::session> management_session_;
  std::string dropped_db_name_;
};

Result<std::unique_ptr<TestDbManager>, std::string>
TestDbManager::createWithRandomDbName(
    size_t sessions, logger::LoggerManagerTreePtr log_manager) {
  size_t create_db_attempts = 0;
  static const auto default_creds = getPostgresCredsOrDefault();
  while (create_db_attempts++ < kMaxCreateDbAttempts) {
    auto pg_opts = std::make_unique<PostgresOptions>(
        default_creds,
        getRandomDbName(),
        log_manager->getChild("PostgresOptions")->getLogger());
    auto create_db_result = PgConnectionInit::prepareWorkingDatabase(
                                iroha::StartupWsvDataPolicy::kDrop, *pg_opts)
        |
        [&] {
          return PgConnectionInit::prepareConnectionPool(
              KTimesReconnectionStrategyFactory{kMaxReconnectionAttempts},
              *pg_opts,
              sessions,
              log_manager->getChild("DbConnectionPool"));
        }
        | [&pg_opts](auto &&pool_wrapper) {
            auto db_dropper = std::make_unique<DbDropper>(
                std::make_unique<soci::session>(
                    *soci::factory_postgresql(),
                    pg_opts->maintenanceConnectionString()),
                pg_opts->workingDbName());
            return std::unique_ptr<TestDbManager>(
                new TestDbManager(std::move(pool_wrapper)->connection_pool_,
                                  std::move(db_dropper)));
          };
    if (iroha::expected::hasValue(create_db_result)) {
      return std::move(create_db_result).assumeValue();
    }
  }
  return makeError(
      std::string{"Failed to create new database with random name after "}
      + std::to_string(create_db_attempts) + " attempts.");
}

TestDbManager::~TestDbManager() = default;

std::unique_ptr<soci::session> TestDbManager::getSession() {
  return std::make_unique<soci::session>(*connection_pool_);
}

TestDbManager::TestDbManager(
    std::shared_ptr<soci::connection_pool> connection_pool,
    std::unique_ptr<DbDropper> db_dropper)
    : db_dropper_(std::move(db_dropper)),
      connection_pool_(std::move(connection_pool)) {}
