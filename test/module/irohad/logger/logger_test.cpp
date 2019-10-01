/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "logger/logger_manager.hpp"

TEST(LoggerTest, basicStandaloneLoggerTest) {
  logger::LoggerConfig config;
  config.log_level = logger::LogLevel::kInfo;
  logger::LoggerManagerTree manager(
      std::make_unique<const logger::LoggerConfig>(std::move(config)));
  auto a_logger = manager.getChild("test info logger")->getLogger();
  a_logger->trace("testing a standalone logger: trace");
  a_logger->info("testing a standalone logger: info");
  a_logger->error("testing a standalone logger: error");
}

TEST(LoggerTest, boolReprTest) {
  ASSERT_EQ("true", logger::boolRepr(true));
  ASSERT_EQ("false", logger::boolRepr(false));
}
