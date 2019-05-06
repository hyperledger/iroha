/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "logger/logger_manager.hpp"

#include <atomic>
#include <ciso646>

static const std::string kTagHierarchySeparator = "/";

static inline std::string joinTags(const std::string &parent,
                                   const std::string &child) {
  return parent.empty() ? child : parent + kTagHierarchySeparator + child;
}

namespace logger {

  LoggerManagerTree::LoggerManagerTree(ConstLoggerConfigPtr config)
      : config_(std::move(config)){};

  LoggerManagerTree::LoggerManagerTree(LoggerConfig config)
      : config_(std::make_shared<const LoggerConfig>(std::move(config))){};

  LoggerManagerTree::LoggerManagerTree(std::string full_tag,
                                       std::string node_tag,
                                       ConstLoggerConfigPtr config)
      : node_tag_(std::move(node_tag)),
        full_tag_(std::move(full_tag)),
        config_(std::move(config)){};

  LoggerManagerTreePtr LoggerManagerTree::registerChild(
      std::string tag,
      boost::optional<LogLevel> log_level,
      boost::optional<LogPatterns> patterns) {
    LoggerConfig child_config{
        log_level.value_or(config_->log_level),
        patterns ? std::move(patterns)->inherit(config_->patterns)
                 : config_->patterns};
    // Operator new is employed due to private visibility of used constructor.
    LoggerManagerTreePtr child(new LoggerManagerTree(
        joinTags(full_tag_, tag),
        tag,
        std::make_shared<const LoggerConfig>(std::move(child_config))));
    auto map_elem = std::make_pair<const std::string, LoggerManagerTreePtr>(
        std::move(tag), std::move(child));
    std::lock_guard<std::mutex> lock(children_mutex_);
    return children_.emplace(std::move(map_elem)).first->second;
  }

  LoggerPtr LoggerManagerTree::getLogger() {
    LoggerPtr logger =
        std::atomic_load_explicit(&logger_, std::memory_order_acquire);
    if (not logger) {
      LoggerPtr new_logger = std::make_shared<LoggerSpdlog>(full_tag_, config_);
      while (not logger) {
        if (std::atomic_compare_exchange_weak_explicit(
                &logger_,
                &logger,
                new_logger,
                std::memory_order_release,
                std::memory_order_acquire)) {
          return new_logger;
        }
      }
    }
    return logger;
  }

  LoggerManagerTreePtr LoggerManagerTree::getChild(const std::string &tag) {
    std::lock_guard<std::mutex> lock(children_mutex_);
    const auto child_it = children_.find(tag);
    if (child_it != children_.end()) {
      return child_it->second;
    }
    // If a node for this child is not found in the tree config, create a
    // new standalone logger using this logger's settings.
    LoggerManagerTreePtr new_child(
        new LoggerManagerTree(joinTags(full_tag_, tag), tag, config_));
    return children_.emplace(std::make_pair(tag, std::move(new_child)))
        .first->second;
  }

}  // namespace logger
