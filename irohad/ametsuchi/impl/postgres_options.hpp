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
     * Type for convenient parse and accessing postres options from pg_opt
     * string
     */
    class PostgresOptions {
     public:
      /**
       * @param pg_opt The connection options string.
       * @param default_dbname The default name of database to use when one is
       * not provided in pg_opt.
       * @param log Logger for internal messages.
       *
       * TODO 2019.06.07 mboldyrev IR-556 make dbname required & remove the
       * default.
       */
      PostgresOptions(const std::string &pg_opt,
                      std::string default_dbname,
                      logger::LoggerPtr log);

      /**
       * @return full pg_opt string with options
       */
      std::string optionsString() const;

      /**
       * @return pg_opt string without dbname param
       */
      std::string optionsStringWithoutDbName() const;

      const std::string &dbname() const;

     private:
      const std::string pg_opt_;
      std::string pg_opt_without_db_name_;
      std::string dbname_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_OPTIONS_HPP
