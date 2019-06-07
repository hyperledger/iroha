/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_options.hpp"

#include <cctype>
#include <regex>

#include <boost/algorithm/string.hpp>
#include "logger/logger.hpp"

namespace iroha {
  namespace ametsuchi {

    // regex to fetch dbname from pg_opt string
    const static std::regex e("\\bdbname=([^ ]*)");

    PostgresOptions::PostgresOptions(const std::string &pg_opt,
                                     std::string default_dbname,
                                     logger::LoggerPtr log)
        : pg_opt_(pg_opt) {
      std::smatch m;

      if (std::regex_search(pg_opt_, m, e)) {
        dbname_ = *(m.end() - 1);

        // get pg_opt_without_db_name_
        pg_opt_without_db_name_ = m.prefix().str() + m.suffix().str();

        // remove consecutive spaces
        auto end =
            std::unique(pg_opt_without_db_name_.begin(),
                        pg_opt_without_db_name_.end(),
                        [](char l, char r) {
                          return std::isspace(l) && std::isspace(r) && l == r;
                        });
        pg_opt_without_db_name_ =
            std::string(pg_opt_without_db_name_.begin(), end);
      } else {
        log->warn(
            "Database name not provided. Using default one: \"{}\". This "
            "behaviour is deprecated!",
            default_dbname);
        dbname_ = std::move(default_dbname);
        pg_opt_without_db_name_ = pg_opt_;
      }
    }

    std::string PostgresOptions::optionsString() const {
      return pg_opt_;
    }

    std::string PostgresOptions::optionsStringWithoutDbName() const {
      return pg_opt_without_db_name_;
    }

    const std::string &PostgresOptions::dbname() const {
      return dbname_;
    }

  }  // namespace ametsuchi
}  // namespace iroha
