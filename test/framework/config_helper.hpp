/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONFIG_HELPER_HPP
#define IROHA_CONFIG_HELPER_HPP

#include <optional>
#include <string>

namespace integration_framework {
  extern const std::string kDefaultWorkingDatabaseName;

  std::string getPostgresCredsOrDefault();

  std::optional<std::string> getPostgresCredsFromEnv();

  std::string getRandomDbName();
}  // namespace integration_framework

#endif  // IROHA_CONFIG_HELPER_HPP
