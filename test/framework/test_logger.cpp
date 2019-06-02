/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/test_logger.hpp"

#include "logger/logger_manager.hpp"

logger::LoggerManagerTreePtr getTestLoggerManager(
    const logger::LogLevel &log_level) {
  static logger::LoggerManagerTreePtr log_manager(
      std::make_shared<logger::LoggerManagerTree>(
          logger::LoggerConfig{log_level, logger::getDefaultLogPatterns()}));
  return log_manager->getChild("Test");
}

logger::LoggerPtr getTestLogger(const std::string &tag) {
  return getTestLoggerManager()->getChild(tag)->getLogger();
}
