/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_DB_MANAGER_HPP
#define TEST_DB_MANAGER_HPP

#include "common/result.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace soci {
  class connection_pool;
  class session;
}  // namespace soci

namespace iroha {
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
       * (@see ::integration_framework::getPostgresCredsOrDefault()). Prepares
       * the schema in the newly created database.
       *
       * @param sessions The number of sessions to create.
       * @param log_manager A log manager to create loggers for child objects.
       * @return TestDbManager instance on success, or string error otherwise.
       */
      static iroha::expected::Result<std::unique_ptr<TestDbManager>,
                                     std::string>
      createWithRandomDbName(size_t sessions,
                             logger::LoggerManagerTreePtr log_manager);

      ~TestDbManager();

      /// Get a session.
      std::unique_ptr<soci::session> getSession();

     private:
      class DbDropper;

      TestDbManager(std::shared_ptr<soci::connection_pool> connection_pool,
                    std::unique_ptr<DbDropper> db_dropper);

      const std::unique_ptr<DbDropper> db_dropper_;

      const std::shared_ptr<soci::connection_pool> connection_pool_;
    };
  }  // namespace integration_framework
}  // namespace iroha

#endif /* TEST_DB_MANAGER_HPP */
