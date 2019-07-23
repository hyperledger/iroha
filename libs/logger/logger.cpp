/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logger/logger.hpp"

namespace logger {

  const LogLevel kDefaultLogLevel = LogLevel::kInfo;

  std::string boolRepr(bool value) {
    return value ? "true" : "false";
  }

}  // namespace logger
