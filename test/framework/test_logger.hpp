/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef TEST_FRAMEWORK_TEST_LOGGER_HPP
#define TEST_FRAMEWORK_TEST_LOGGER_HPP

#include "logger/logger_fwd.hpp"
#include "logger/logger_manager_fwd.hpp"

logger::LoggerManagerTreePtr getTestLoggerManager();

logger::LoggerPtr getTestLogger(const std::string &tag);

#endif  // TEST_FRAMEWORK_TEST_LOGGER_HPP
