/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logger/logger_spdlog.hpp"

#include <atomic>
#include <ciso646>
#include <mutex>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <boost/assert.hpp>

namespace {

  spdlog::level::level_enum getSpdlogLogLevel(logger::LogLevel level) {
    switch (level) {
      case logger::LogLevel::kTrace:
        return spdlog::level::trace;
      case logger::LogLevel::kDebug:
        return spdlog::level::debug;
      case logger::LogLevel::kInfo:
        return spdlog::level::info;
      case logger::LogLevel::kWarn:
        return spdlog::level::warn;
      case logger::LogLevel::kError:
        return spdlog::level::err;
      case logger::LogLevel::kCritical:
        return spdlog::level::critical;
      default:
        BOOST_ASSERT_MSG(false, "Unknown log level!");
        return spdlog::level::info;
    }
  }

  std::shared_ptr<spdlog::logger> getOrCreateLogger(const std::string tag) {
    std::shared_ptr<spdlog::logger> logger;
    try {
      logger = spdlog::stdout_color_mt(tag);
    } catch (const spdlog::spdlog_ex &) {
      logger = spdlog::get(tag);
    }
    assert(logger);
    return logger;
  }

}  // namespace

namespace logger {

  LogPatterns getDefaultLogPatterns() {
    static std::atomic_flag is_initialized = ATOMIC_FLAG_INIT;
    static LogPatterns default_patterns;
    if (not is_initialized.test_and_set()) {
      default_patterns.setPattern(
          LogLevel::kTrace, R"([%Y-%m-%d %H:%M:%S.%F][th:%t][%=8l][%n]: %v)");
      default_patterns.setPattern(LogLevel::kInfo,
                                  R"([%Y-%m-%d %H:%M:%S.%F][%L][%n]: %v)");
    }
    return default_patterns;
  }

  void LogPatterns::setPattern(LogLevel level, std::string pattern) {
    patterns_[level] = pattern;
  }

  std::string LogPatterns::getPattern(LogLevel level) const {
    for (auto it = patterns_.rbegin(); it != patterns_.rend(); ++it) {
      if (it->first <= level) {
        return it->second;
      }
    }
    return getDefaultLogPatterns().getPattern(level);
  }

  LogPatterns &LogPatterns::inherit(const LogPatterns &base) {
    if (patterns_.empty()) {
      patterns_ = base.patterns_;
    } else {
      for (auto it = base.patterns_.cbegin();
           it != base.patterns_.cend() and it->first < patterns_.begin()->first;
           ++it) {
        patterns_.emplace(*it);
      }
    }
    return *this;
  }

  LoggerSpdlog::LoggerSpdlog(std::string tag, ConstLoggerConfigPtr config)
      : tag_(tag), config_(std::move(config)), logger_(getOrCreateLogger(tag)) {
    setupLogger();
  }

  void LoggerSpdlog::setupLogger() {
    logger_->set_level(getSpdlogLogLevel(config_->log_level));
    logger_->set_pattern(config_->patterns.getPattern(config_->log_level));
  }

  void LoggerSpdlog::logInternal(Level level, const std::string &s) const {
    logger_->log(getSpdlogLogLevel(level), s);
  }

  bool LoggerSpdlog::shouldLog(Level level) const {
    return config_->log_level <= level;
  }
}  // namespace logger
