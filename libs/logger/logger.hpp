/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LOGGER_LOGGER_HPP
#define IROHA_LOGGER_LOGGER_HPP

#include "logger/logger_fwd.hpp"

#include <string>

#include <fmt/core.h>
#include <fmt/format.h>
// Windows includes transitively included by format.h define interface as
// struct, leading to compilation issues
#undef interface

namespace fmt {
  /// Allows to log objects, which have toString() method without calling it,
  /// e.g. log.info("{}", myObject)
  template <typename T>
  struct formatter<
      T,
      std::enable_if_t<std::is_same<decltype(std::declval<T>().toString()),
                                    std::string>::value,
                       char>> {
    // The following functions are not defined intentionally.
    template <typename ParseContext>
    auto parse(ParseContext &ctx) -> decltype(ctx.begin()) {
      return ctx.begin();
    }

    template <typename FormatContext>
    auto format(const T &val, FormatContext &ctx) -> decltype(ctx.out()) {
      return format_to(ctx.out(), "{}", val.toString());
    }
  };
}  // namespace fmt

namespace logger {

  enum class LogLevel;

  extern const LogLevel kDefaultLogLevel;

  /// Log levels
  enum class LogLevel {
    kTrace,
    kDebug,
    kInfo,
    kWarn,
    kError,
    kCritical,
  };

  class Logger {
   public:
    using Level = LogLevel;

    virtual ~Logger() = default;

    // --- Logging functions ---

    template <typename... Args>
    void trace(const std::string &format, const Args &... args) const {
      log(LogLevel::kTrace, format, args...);
    }

    template <typename... Args>
    void debug(const std::string &format, const Args &... args) const {
      log(LogLevel::kDebug, format, args...);
    }

    template <typename... Args>
    void info(const std::string &format, const Args &... args) const {
      log(LogLevel::kInfo, format, args...);
    }

    template <typename... Args>
    void warn(const std::string &format, const Args &... args) const {
      log(LogLevel::kWarn, format, args...);
    }

    template <typename... Args>
    void error(const std::string &format, const Args &... args) const {
      log(LogLevel::kError, format, args...);
    }

    template <typename... Args>
    void critical(const std::string &format, const Args &... args) const {
      log(LogLevel::kCritical, format, args...);
    }

    template <typename... Args>
    void log(Level level,
             const std::string &format,
             const Args &... args) const {
      if (shouldLog(level)) {
        try {
          logInternal(level, fmt::format(format, args...));
        } catch (const std::exception &error) {
          std::string error_msg("Exception was thrown while logging: ");
          logInternal(LogLevel::kError, error_msg.append(error.what()));
        }
      }
    }

   protected:
    virtual void logInternal(Level level, const std::string &s) const = 0;

    /// Whether the configured logging level is at least as verbose as the
    /// one given in parameter.
    virtual bool shouldLog(Level level) const = 0;
  };

  /**
   * Convert bool value to human readable string repr
   * @param value value for transformation
   * @return "true" or "false"
   */
  std::string boolRepr(bool value);

}  // namespace logger

#endif  // IROHA_LOGGER_LOGGER_HPP
