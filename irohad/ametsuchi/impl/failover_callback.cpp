/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/failover_callback.hpp"

#include <ciso646>

#include <soci/postgresql/soci-postgresql.h>

#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

FailoverCallback::FailoverCallback(
    soci::session &connection,
    InitFunctionType init,
    std::string connection_options,
    std::unique_ptr<ReconnectionStrategy> reconnection_strategy,
    logger::LoggerPtr log)
    : connection_(connection),
      init_session_(std::move(init)),
      connection_options_(std::move(connection_options)),
      reconnection_strategy_(std::move(reconnection_strategy)),
      log_(std::move(log)) {}

void FailoverCallback::started() {
  reconnection_strategy_->reset();
  log_->debug("Reconnection process is initiated");
}

void FailoverCallback::finished(soci::session &) {}

void FailoverCallback::failed(bool &should_reconnect, std::string &) {
  // don't rely on reconnection in soci because we are going to conduct
  // our own reconnection process
  should_reconnect = false;
  log_->warn(
      "failed to connect to the database. The system will try to "
      "reconnect");
  auto is_reconnected = reconnectionLoop();
  log_->info("re-established: {}", is_reconnected);
}

void FailoverCallback::aborted() {
  log_->error("has invoked aborted method of FailoverCallback");
}

bool FailoverCallback::reconnectionLoop() {
  bool successful_reconnection = false;
  while (reconnection_strategy_->canReconnect()
         and not successful_reconnection) {
    try {
      soci::connection_parameters parameters(*soci::factory_postgresql(),
                                             connection_options_);
      auto *pg_connection = static_cast<soci::postgresql_session_backend *>(
          connection_.get_backend());
      auto &conn_ = pg_connection->conn_;

      auto clean_up = [](auto &conn_) {
        if (0 != conn_) {
          PQfinish(conn_);
          conn_ = 0;
        }
      };

      auto check_for_data = [](auto &conn, auto *result, auto *errMsg) {
        std::string msg(errMsg);

        ExecStatusType const status = PQresultStatus(result);
        switch (status) {
          case PGRES_EMPTY_QUERY:
          case PGRES_COMMAND_OK:
            // No data but don't throw neither.
            return false;

          case PGRES_TUPLES_OK:
            return true;

          case PGRES_FATAL_ERROR:
            msg += " Fatal error.";

            if (PQstatus(conn) == CONNECTION_BAD) {
              msg += " Connection failed.";
            }

            break;

          default:
            // Some of the other status codes are not really errors
            // but we're not prepared to handle them right now and
            // shouldn't ever receive them so throw nevertheless

            break;
        }

        const char *const pqError = PQresultErrorMessage(result);
        if (pqError && *pqError) {
          msg += " ";
          msg += pqError;
        }

        const char *sqlstate = PQresultErrorField(result, PG_DIAG_SQLSTATE);
        const char *const blank_sql_state = "     ";
        if (!sqlstate) {
          sqlstate = blank_sql_state;
        }

        throw std::runtime_error(msg);
      };

      auto connect = [check_for_data](auto &conn, auto &parameters) {
        PGconn *new_conn = PQconnectdb(parameters.get_connect_string().c_str());
        if (0 == new_conn || CONNECTION_OK != PQstatus(new_conn)) {
          std::string msg = "Cannot establish connection to the database.";
          if (0 != new_conn) {
            msg += '\n';
            msg += PQerrorMessage(new_conn);
            PQfinish(new_conn);
          }

          throw std::runtime_error(msg);
        }

        // Increase the number of digits used for floating point values to
        // ensure that the conversions to/from text round trip correctly,
        // which is not the case with the default value of 0. Use the
        // maximal supported value, which was 2 until 9.x and is 3 since
        // it.
        int const version = PQserverVersion(new_conn);
        check_for_data(new_conn,
                       PQexec(new_conn,
                              version >= 90000 ? "SET extra_float_digits = 3"
                                               : "SET extra_float_digits = 2"),
                       "Cannot set extra_float_digits parameter");

        conn = new_conn;
      };

      clean_up(conn_);
      connect(conn_, parameters);

      init_session_(connection_);
      successful_reconnection = true;
    } catch (const std::exception &e) {
      log_->warn("attempt to reconnect has failed: {}", e.what());
    }
  }
  return successful_reconnection;
}
