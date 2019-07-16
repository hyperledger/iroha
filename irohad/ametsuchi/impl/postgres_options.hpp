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
       * @param pg_creds The connection credentials string.
       * @param working_dbname The name of working database. Gets overriden by
       * pg_creds (this override is deprecated).
       * @param maintenance_dbname The name of database for maintenance
       * purposes. It will not be altered in any way and is used to manage
       * working database.
       * @param log Logger for internal messages.
       *
       * TODO 2019.06.07 mboldyrev IR-556 remove the override info above.
       */
      PostgresOptions(const std::string &pg_creds,
                      std::string working_dbname,
                      std::string maintenance_dbname,
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

     private:
      std::string getConnectionStringWithDbName(
          const std::string &dbname) const;

      // TODO 2019.06.26 mboldyrev IR-556 make pg_creds_ and working_dbname_
      // const
      std::string pg_creds_;
      std::string working_dbname_;
      const std::string maintenance_dbname_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_OPTIONS_HPP
