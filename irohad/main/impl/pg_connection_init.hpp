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

#include "ametsuchi/impl/failover_callback_factory.hpp"
#include "ametsuchi/impl/pool_wrapper.hpp"
#include "ametsuchi/impl/postgres_command_executor.hpp"
#include "ametsuchi/impl/postgres_options.hpp"
#include "ametsuchi/reconnection_strategy.hpp"
#include "common/result.hpp"
#include "interfaces/permissions.hpp"
#include "logger/logger_manager.hpp"

namespace iroha {
  namespace ametsuchi {
    inline std::string formatPostgresMessage(const char *message) {
      std::string formatted_message(message);
      boost::replace_if(formatted_message, boost::is_any_of("\r\n"), ' ');
      return formatted_message;
    }

    inline void processPqNotice(void *arg, const char *message) {
      auto *log = reinterpret_cast<logger::Logger *>(arg);
      log->debug("{}", formatPostgresMessage(message));
    }

    class PgConnectionInit {
     public:
      expected::Result<std::shared_ptr<soci::connection_pool>, std::string>
      initPostgresConnection(std::string &options_str, size_t pool_size);

      expected::Result<std::shared_ptr<PoolWrapper>, std::string>
      prepareConnectionPool(
          ReconnectionStrategyFactory &reconnection_strategy_factory,
          const PostgresOptions &options,
          logger::LoggerManagerTreePtr log_manager);

      /**
       * Verify whether postgres supports prepared transactions
       */
      bool preparedTransactionsAvailable(soci::session &sql);

      static iroha::expected::Result<void, std::string> rollbackPrepared(
          soci::session &sql, const std::string &prepared_block_name);

      expected::Result<bool, std::string> createDatabaseIfNotExist(
          const std::string &dbname,
          const std::string &options_str_without_dbname);

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
          PostgresCommandExecutor::prepareStatements(session);
        };

        /// lambda contains special actions which should be execute once
        auto init_db = [&](soci::session &session) {
          // rollback current prepared transaction
          // if there exists any since last session
          try_rollback(session);
          session << prepare_tables_sql;
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

        initialize_session(
            connection_pool.at(0), init_db, init_failover_callback);
        for (size_t i = 1; i != pool_size; i++) {
          soci::session &session = connection_pool.at(i);
          initialize_session(session, [](auto &) {}, init_failover_callback);
        }
      }

      static const std::string kDefaultDatabaseName;

      static const std::string init_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_PG_CONNECTION_INIT_HPP
