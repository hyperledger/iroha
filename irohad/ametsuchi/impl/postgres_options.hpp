/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_OPTIONS_HPP
#define IROHA_POSTGRES_OPTIONS_HPP

#include <unordered_map>
#include "common/result.hpp"
#include "logger/logger_fwd.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Type for convenient formatting of PostgreSQL connection strings.
     */
    class PostgresOptions {
     public:
      /**
       * @param pg_opt The connection options string.
       * @param default_dbname The default name of database to use when one is
       * not provided in pg_opt.
       * @param log Logger for internal messages.
       *
       * TODO 2019.06.07 mboldyrev IR-556 remove this constructor
       */
      PostgresOptions(const std::string &pg_opt,
                      std::string default_dbname,
                      logger::LoggerPtr log);

      /**
       * @param host PostgreSQL host.
       * @param port PostgreSQL port.
       * @param user PostgreSQL username.
       * @param password PostgreSQL password.
       * @param working_dbname The name of working database.
       * @param maintenance_dbname The name of database for maintenance
       * purposes. It will not be altered in any way and is used to manage
       * working database.
       * @param log Logger for internal messages.
       */
      PostgresOptions(const std::string &host,
                      uint16_t port,
                      const std::string &user,
                      const std::string &password,
                      const std::string &working_dbname,
                      const std::string &maintenance_dbname,
                      logger::LoggerPtr log);

      /// @return connection string without dbname param
      std::string connectionStringWithoutDbName() const;

      /// @return connection string to working database
      std::string workingConnectionString() const;

      /// @return connection string to maintenance database
      std::string maintenanceConnectionString() const;

      /// @return working database name
      std::string workingDbName() const;

      /// @return maintenance database name
      std::string maintenanceDbName() const;

      /// @return prepared block name
      const std::string &preparedBlockName() const;

     private:
      std::string getConnectionStringWithDbName(
          const std::string &dbname) const;

      const std::string host_;
      const uint16_t port_;
      const std::string user_;
      const std::string password_;
      const std::string working_dbname_;
      const std::string maintenance_dbname_;
      const std::string prepared_block_name_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_OPTIONS_HPP
