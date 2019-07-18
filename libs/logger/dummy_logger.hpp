/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef LOGGER_DUMMY_LOGGER_HPP
#define LOGGER_DUMMY_LOGGER_HPP

#include "logger/logger.hpp"

namespace logger {

  class DummyLogger : public Logger {
   protected:
    void logInternal(Level level, const std::string &s) const override {}

    bool shouldLog(Level level) const override {
      return false;
    }
  };

  LoggerPtr getDummyLoggerPtr() {
    static std::shared_ptr<DummyLogger> log = std::make_shared<DummyLogger>();
    return log;
  }

}  // namespace logger

#endif  // LOGGER_DUMMY_LOGGER_HPP
