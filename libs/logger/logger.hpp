/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LOGGER_LOGGER_HPP
#define IROHA_LOGGER_LOGGER_HPP

#include "logger/logger_fwd.hpp"

#include <memory>
#include <numeric>  // for std::accumulate
#include <string>

/// Allows to log objects, which have toString() method without calling it, e.g.
/// log.info("{}", myObject)
template <typename StreamType, typename T>
auto operator<<(StreamType &os, const T &object)
    -> decltype(os << object.toString()) {
  return os << object.toString();
}

#include <fmt/format.h>
#include <fmt/ostream.h>

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
         logInternal(level, fmt::format(format, args...));
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

  /**
   * Converts object to bool and provides string repr of it
   * @tparam T - type of object, T must implement bool operator
   * @param val - value for convertation
   * @return string representation of bool object
   */
  template <typename T>
  std::string logBool(T val) {
    return boolRepr(bool(val));
  }

  /**
   * Function provide string representation of collection
   * @tparam Collection - type should implement for semantic
   * @tparam Lambda - function that transform argument to string
   * @param collection - bunch of objects
   * @param transform - function that convert object to string
   * @return string repr of collection
   */
  template <class Collection, class Lambda>
  std::string to_string(const Collection &collection, Lambda transform) {
    const std::string left_bracket = "{";
    const std::string right_bracket = "}";
    const std::string separator = ", ";
    auto begin = collection.size() == 0 ? collection.begin()
                                        : std::next(collection.begin());
    auto front =
        collection.size() == 0 ? std::string{} : transform(*collection.begin());

    auto result = std::accumulate(begin,
                                  collection.end(),
                                  front.insert(0, left_bracket),
                                  [&](auto &acc, const auto &value) {
                                    acc += separator;
                                    acc += transform(value);
                                    return acc;
                                  });
    return result.append(right_bracket);
  }

  /**
   * Function provide string representation of optional value
   * @tparam Optional - type of optional
   * @tparam Lambda - function that consume value type and return std::string
   * @param opt - value wrapped by optional
   * @param transform - function that transforming value to std::string
   * @return string repr of value
   */
  template <class Optional, class Lambda>
  std::string opt_to_string(const Optional &opt, Lambda transform) {
    const std::string null_value = "nullopt";
    return opt ? null_value : transform(*opt);
  }

}  // namespace logger

#endif  // IROHA_LOGGER_LOGGER_HPP
