/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PG_CONNECTION_INIT_HPP
#define IROHA_PG_CONNECTION_INIT_HPP

#include <soci/soci.h>

#include <soci/callbacks.h>
#include <soci/postgresql/soci-postgresql.h>
#include <boost/algorithm/string.hpp>
#include <boost/range/algorithm/replace_if.hpp>

#include "ametsuchi/impl/failover_callback_holder.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/reconnection_strategy.hpp"
#include "common/result.hpp"
#include "interfaces/permissions.hpp"
#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

namespace iroha {
  namespace ametsuchi {
    class PgConnectionInit {
     public:
      static expected::Result<std::shared_ptr<soci::connection_pool>,
                              std::string>
      initPostgresConnection(std::string &options_str, size_t pool_size);

      static expected::Result<void, std::string> prepareWorkingDatabase(
          const bool keep_wsv_data, const PostgresOptions &options);

      static expected::Result<PoolWrapper, std::string> prepareConnectionPool(
          const ReconnectionStrategyFactory &reconnection_strategy_factory,
          const PostgresOptions &options,
          const int pool_size,
          logger::LoggerManagerTreePtr log_manager);

      /**
       * Verify whether postgres supports prepared transactions
       */
      static bool preparedTransactionsAvailable(soci::session &sql);

      static iroha::expected::Result<void, std::string> rollbackPrepared(
          soci::session &sql, const std::string &prepared_block_name);

      /**
       * Removes all peers from WSV
       * @return error message if reset has failed
       */
      static expected::Result<void, std::string> resetPeers(soci::session &sql);

      /**
       * Creates schema. Working database must not exist when calling this.
       * @return void value in case of success or an error message otherwise.
       */
      static expected::Result<void, std::string> createSchema(
          const PostgresOptions &postgres_options);

      /*
       * Drop the working database if it exists.
       * @param postgres_options Database options.
       * @return Result of void value on success, otherwise error message
       */
      static expected::Result<void, std::string> dropSchema(
          const PostgresOptions &postgres_options);

     private:
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
      static expected::Result<void, std::string> initializeConnectionPool(
          soci::connection_pool &connection_pool,
          size_t pool_size,
          RollbackFunction try_rollback,
          FailoverCallbackHolder &callback_factory,
          const ReconnectionStrategyFactory &reconnection_strategy_factory,
          const std::string &pg_reconnection_options,
          logger::LoggerManagerTreePtr log_manager);

     public:
      static const std::string prepare_database_sql_;
      static const std::string prepare_tables_sql_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_PG_CONNECTION_INIT_HPP
