/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_OPTIONS_HPP
#define IROHA_POSTGRES_OPTIONS_HPP

#include <boost/optional.hpp>
#include <unordered_map>
#include "common/result.hpp"

namespace iroha {
  namespace ametsuchi {

    /**
     * Type for convenient parse and accessing postres options from pg_opt
     * string
     */
    class PostgresOptions {
     public:

      /**
       * Prohibit initialization of the PostgresOptions with no params
       */
      PostgresOptions() = delete;

      /**
       * @return full pg_opt string with options
       */
      std::string optionsString() const;

      /**
       * @return pg_opt string without dbname param
       */
      std::string optionsStringWithoutDbName() const;

      boost::optional<std::string> dbname() const;

      explicit PostgresOptions(const std::string &pg_opt);

     private:
      const std::string pg_opt_;
      std::string pg_opt_without_db_name_;
      boost::optional<std::string> dbname_;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_OPTIONS_HPP
