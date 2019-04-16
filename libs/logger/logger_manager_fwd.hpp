/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SPDLOG_LOGGER_MANAGER_FWD_HPP
#define IROHA_SPDLOG_LOGGER_MANAGER_FWD_HPP

#include <memory>

namespace logger {

  class LoggerManagerTree;
  using LoggerManagerTreePtr = std::shared_ptr<LoggerManagerTree>;

}  // namespace logger

#endif  // IROHA_SPDLOG_LOGGER_MANAGER_FWD_HPP
