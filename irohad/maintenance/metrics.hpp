/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MAINTENANCE_METRICS_HPP
#define IROHA_MAINTENANCE_METRICS_HPP

#include <string>
#include <memory>
#include <optional>
#include <thread>
#include <prometheus/registry.h>
#include <prometheus/exposer.h>

//struct MetricsRunner : std::thread {
////  metrics_runner(std::thread&&t):t_(t){};
//  using std::thread::thread;  // Does not inherit move ctor?
//  MetricsRunner(MetricsRunner&&m)noexcept
//      : std::thread(std::move(m))
//      ,
//  {}
//  ~MetricsRunner(){ stop(); join(); }
//  void stop(){ proceed_.clear(); };
// private:
////  std::thread t_;
//  std::atomic_flag proceed_ {true};
//};
struct Metrics {
  std::shared_ptr<prometheus::Registry> registry;
  std::shared_ptr<prometheus::Exposer> exposer;
//  MetricsRunner runner;
};
std::optional<Metrics> maintenance_metrics_init(std::string const& listen_addr);

#endif //IROHA_MAINTENANCE_METRICS_HPP
