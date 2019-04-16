/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SPDLOG_LOGGER_MANAGER_HPP
#define IROHA_SPDLOG_LOGGER_MANAGER_HPP

#include "logger/logger_manager_fwd.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <boost/optional.hpp>
#include "logger/logger_spdlog.hpp"

namespace logger {

  /**
   * A node of logger managers tree. It stores the configuration needed to
   * create a logger corresponding to this node and its children. Thread safe.
   */
  class LoggerManagerTree {
   public:
    explicit LoggerManagerTree(ConstLoggerConfigPtr config);

    explicit LoggerManagerTree(LoggerConfig config);

    /**
     * Register a child configuration. The new child's configuration parameters
     * are taken from the parent optionally overrided by the arguments. Thread
     * safe.
     *
     * @param tag - the child's tag, without any parents' prefixes
     * @param log_level - override the log level for the new child
     * @param patterns - override the patterns
     */
    LoggerManagerTreePtr registerChild(std::string tag,
                                       boost::optional<LogLevel> log_level,
                                       boost::optional<LogPatterns> patterns);

    /// Get this node's logger. Thread safe.
    LoggerPtr getLogger();

    /// Get non-const child node by tag, if present. Thread safe.
    LoggerManagerTreePtr getChild(const std::string &tag);

   private:
    LoggerManagerTree(std::string full_tag,
                      std::string node_tag,
                      ConstLoggerConfigPtr config);

    const std::string node_tag_;
    const std::string full_tag_;
    const ConstLoggerConfigPtr config_;
    std::shared_ptr<Logger> logger_;
    std::unordered_map<std::string, LoggerManagerTreePtr> children_;
    std::mutex children_mutex_;
  };

}  // namespace logger

#endif  // IROHA_SPDLOG_LOGGER_MANAGER_HPP
