/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/config_helper.hpp"

#include <ciso646>
#include <sstream>

#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>

namespace integration_framework {
  const std::string kDefaultWorkingDatabaseName{"iroha_default"};

  std::string getPostgresCredsOrDefault() {
    static const std::string kDefaultPostgresCreds =
        "host=localhost "
        "port=5432 "
        "user=postgres "
        "password=mysecretpassword";
    return getPostgresCredsFromEnv().value_or(kDefaultPostgresCreds);
  }

  boost::optional<std::string> getPostgresCredsFromEnv() {
    auto pg_host = std::getenv("IROHA_POSTGRES_HOST");
    auto pg_port = std::getenv("IROHA_POSTGRES_PORT");
    auto pg_user = std::getenv("IROHA_POSTGRES_USER");
    auto pg_pass = std::getenv("IROHA_POSTGRES_PASSWORD");

    if (pg_host and pg_port and pg_user and pg_pass) {
      std::stringstream ss;
      ss << "host=" << pg_host << " port=" << pg_port << " user=" << pg_user
         << " password=" << pg_pass;
      return ss.str();
    }
    return {};
  }

  std::string getRandomDbName() {
    return std::string{"test_db_"}  // must begin with a letter or underscore
    + boost::uuids::to_string(boost::uuids::random_generator()()).substr(0, 8);
  }
}  // namespace integration_framework
