/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/config_helper.hpp"

#include <ciso646>
#include <sstream>

namespace integration_framework {

  std::string getPostgresCredsOrDefault(const std::string &default_conn) {
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
    return default_conn;
  }
}  // namespace integration_framework
