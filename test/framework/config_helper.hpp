/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONFIG_HELPER_HPP
#define IROHA_CONFIG_HELPER_HPP

#include <string>

namespace integration_framework {
  std::string getPostgresCredsOrDefault(const std::string &default_conn =
                                            "host=localhost port=5432 "
                                            "user=postgres "
                                            "password=mysecretpassword");
}  // namespace integration_framework

#endif  // IROHA_CONFIG_HELPER_HPP
