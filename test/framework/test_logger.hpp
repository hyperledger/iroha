/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_FRAMEWORK_TEST_LOGGER_HPP
#define TEST_FRAMEWORK_TEST_LOGGER_HPP

#include "logger/logger.hpp"
#include "logger/logger_manager_fwd.hpp"

logger::LoggerManagerTreePtr getTestLoggerManager(
    const logger::LogLevel &log_level = logger::LogLevel::kDebug);

logger::LoggerPtr getTestLogger(const std::string &tag);

#endif  // TEST_FRAMEWORK_TEST_LOGGER_HPP
