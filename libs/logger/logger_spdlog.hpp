/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LOGGER_SPDLOG_HPP
#define IROHA_LOGGER_SPDLOG_HPP

#include "logger/logger.hpp"

#include <map>
#include <memory>
#include <string>

namespace spdlog {
  class logger;
}

namespace logger {

  class LogPatterns;
  struct LoggerConfig;

  using ConstLoggerConfigPtr = std::shared_ptr<const LoggerConfig>;

  LogPatterns getDefaultLogPatterns();

  /// Patterns for logging depending on the log level.
  class LogPatterns {
   public:
    /// Set a logging pattern for the given level.
    void setPattern(LogLevel level, std::string pattern);

    /**
     * Get the logging pattern for the given level. If not set, get the
     * next present more verbose level pattern, if any, or the default
     * pattern.
     */
    std::string getPattern(LogLevel level) const;

    /// Inherit missing level overrides from another patterns
    LogPatterns &inherit(const LogPatterns &base);

   private:
    std::map<LogLevel, std::string> patterns_;
  };

  // TODO mboldyrev 29.12.2018 IR-188 Add sink options (console, file, syslog)
  struct LoggerConfig {
    LogLevel log_level;
    LogPatterns patterns;
  };

  class LoggerSpdlog : public Logger {
   public:
    /**
     * @param tag - the tag for logging (aka logger name)
     * @param config - logger configuration
     */
    LoggerSpdlog(std::string tag, ConstLoggerConfigPtr config);

   private:
    void logInternal(Level level, const std::string &s) const override;

    /// Whether the configured logging level is at least as verbose as the
    /// one given in parameter.
    bool shouldLog(Level level) const override;

    /// Set Spdlog logger level and pattern.
    void setupLogger();

    const std::string tag_;
    const ConstLoggerConfigPtr config_;
    const std::shared_ptr<spdlog::logger> logger_;
  };

}  // namespace logger

#endif  // IROHA_LOGGER_SPDLOG_HPP
