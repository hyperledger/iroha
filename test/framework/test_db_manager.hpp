/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_DB_MANAGER_HPP
#define TEST_DB_MANAGER_HPP

#include "common/result.hpp"
#include "logger/logger_fwd.hpp"


namespace iroha {
  namespace ametsuchi {
    class PostgresOptions;
  }

  namespace integration_framework {

    /**
     * Manages test database lifecycle.
     * Creates a database to be used in tests. Drops it on being destroyed.
     */
    class TestDbManager {
     public:
      /**
       * Create a new test database with random name. If generated name is
       * already used, it will try several random alphanumeric names more.
       * Attempts to get connection settings from environment variables
       * (@see ::integration_framework::getPostgresCredsOrDefault()).
       * @param pg_opts_log The logger to pass to PostgresOptions constructor.
       * @return TestDbManager instance on success, or string error otherwise.
       */
      static iroha::expected::Result<std::unique_ptr<TestDbManager>,
                                     std::string>
      createWithRandomDbName(logger::LoggerPtr pg_opts_log);

      /// Drops the created database.
      ~TestDbManager();

      /// Provides the connection options for the managed database.
      std::shared_ptr<const iroha::ametsuchi::PostgresOptions>
      getPostgresOptions() const;

     private:
      TestDbManager(
          std::shared_ptr<const iroha::ametsuchi::PostgresOptions> pg_opts);

      const std::shared_ptr<const iroha::ametsuchi::PostgresOptions> pg_opts_;
    };
  }  // namespace integration_framework
}  // namespace iroha

#endif /* TEST_DB_MANAGER_HPP */
