/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/postgres_options.hpp"

#include <cctype>
#include <regex>

#include <boost/algorithm/string.hpp>
#include "logger/logger.hpp"

using namespace iroha::ametsuchi;

namespace {
  void removeConsequtiveSimilarSpaces(std::string &s) {
    auto end = std::unique(s.begin(), s.end(), [](char l, char r) {
      return std::isspace(l) && std::isspace(r) && l == r;
    });
    s.erase(end, s.end());
  }
}  // namespace

PostgresOptions::PostgresOptions(const std::string &pg_creds,
                                 std::string working_dbname,
                                 std::string maintenance_dbname,
                                 logger::LoggerPtr log)
    : pg_creds_(pg_creds),
      working_dbname_(working_dbname),
      maintenance_dbname_(maintenance_dbname) {
  // regex to extract dbname from pg_creds string
  const static std::regex e("\\bdbname=([^ ]+)");
  std::smatch m;
  if (std::regex_search(pg_creds, m, e)) {
    // TODO 2019.06.26 mboldyrev IR-556 remove assignment and add warning to
    // the log.
    working_dbname_ = m[1];

    // TODO 2019.06.26 mboldyrev IR-556 remove assignment
    pg_creds_ = m.prefix().str() + m.suffix().str();
  } else {
    // TODO 2019.06.26 mboldyrev IR-556 remove this entire `else' block
    log->warn(
        "Database name not provided. Using default one: \"{}\". This "
        "behaviour is deprecated!",
        working_dbname);
    working_dbname_ = std::move(working_dbname);
  }

  removeConsequtiveSimilarSpaces(pg_creds_);
}

std::string PostgresOptions::connectionStringWithoutDbName() const {
  return pg_creds_;
}

std::string PostgresOptions::workingConnectionString() const {
  return getConnectionStringWithDbName(working_dbname_);
}

std::string PostgresOptions::maintenanceConnectionString() const {
  return getConnectionStringWithDbName(maintenance_dbname_);
}

std::string PostgresOptions::getConnectionStringWithDbName(
    const std::string &dbname) const {
  return pg_creds_ + " dbname=" + dbname;
}

std::string PostgresOptions::workingDbName() const {
  return working_dbname_;
}

std::string PostgresOptions::maintenanceDbName() const {
  return maintenance_dbname_;
}
