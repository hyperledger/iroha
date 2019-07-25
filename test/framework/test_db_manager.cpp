/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/test_db_manager.hpp"

#include "ametsuchi/impl/postgres_options.hpp"
#include "framework/config_helper.hpp"
#include "framework/result_gtest_checkers.hpp"
#include "main/impl/pg_connection_init.hpp"

using namespace framework::expected;
using namespace integration_framework;
using namespace iroha::ametsuchi;
using namespace iroha::expected;
using namespace iroha::integration_framework;

static constexpr size_t kMaxRandomDbNameAttempts = 8;

Result<std::unique_ptr<TestDbManager>, std::string>
TestDbManager::createWithRandomDbName(logger::LoggerPtr pg_opts_log) {
  size_t random_db_name_attempts = 0;
  static const auto default_creds = getPostgresCredsOrDefault();
  while (random_db_name_attempts++ < kMaxRandomDbNameAttempts) {
    auto pg_opts = std::make_shared<const PostgresOptions>(
        default_creds, getRandomDbName(), pg_opts_log);
    auto db_exists_result =
        PgConnectionInit::checkIfWorkingDatabaseIfExists(*pg_opts);
    if (auto e = resultToOptionalError(db_exists_result)) {
      return std::move(e).value();
    }
    if (not resultToOptionalValue(db_exists_result).value()) {
      PgConnectionInit::createDatabaseIfNotExist(*pg_opts) |
          [&pg_opts](bool db_was_created) {
            EXPECT_TRUE(db_was_created);
            return std::unique_ptr<TestDbManager>(
                new TestDbManager(std::move(pg_opts)));
          };
    }
  }
  return makeError(
      std::string{"Failed to create new database with random name after "}
      + std::to_string(random_db_name_attempts) + " attempts.");
}

std::shared_ptr<const PostgresOptions> TestDbManager::getPostgresOptions()
    const {
  return pg_opts_;
}

TestDbManager::TestDbManager(std::shared_ptr<const PostgresOptions> pg_opts)
    : pg_opts_(std::move(pg_opts)) {}

TestDbManager::~TestDbManager() {
  expectResultValue(PgConnectionInit::dropWorkingDatabase(*pg_opts_));
}
