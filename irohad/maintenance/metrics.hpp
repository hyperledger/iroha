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
#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "main/subscription.hpp"
#include "network/ordering_gate_common.hpp"

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
class Metrics {
  std::shared_ptr<prometheus::Registry> registry;
  std::shared_ptr<prometheus::Exposer> exposer;
//  MetricsRunner runner;

  using BlockPtr = std::shared_ptr<const shared_model::interface::Block>;
  using BlockSubscriber = iroha::BaseSubscriber<bool,BlockPtr>;
  std::shared_ptr<BlockSubscriber> block_subscriber;

  using OnProposalSubscription = iroha::BaseSubscriber<
      bool,iroha::network::OrderingEvent>;  //FixMe subscribtion ≠ subscriber
  std::shared_ptr<OnProposalSubscription> on_proposal_subscription_;
 public:
  Metrics(
      std::string const& listen_addr,
      shared_model::interface::types::HeightType);

  bool valid()const;
};
std::optional<Metrics> maintenance_metrics_init(
    std::string const& listen_addr, shared_model::interface::types::HeightType);

#endif //IROHA_MAINTENANCE_METRICS_HPP
