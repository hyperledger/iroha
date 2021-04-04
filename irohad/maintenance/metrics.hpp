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
#include "ametsuchi/wsv_query.hpp"
#include "ametsuchi/storage.hpp"
#include "logger/logger_fwd.hpp"


/// ToDo consider using asio::io_context
struct MetricsRunner {//: std::thread {
//  using std::thread::thread;  // Does not inherit move ctor?
////  using std::thread::operator=;
//  MetricsRunner(MetricsRunner&&m)noexcept
//      : std::thread(std::move(m))
////      , proceed_(std::move(std::move(m).proceed_))
//  {}
//  MetricsRunner& operator=(MetricsRunner&&m)noexcept{
//    return *this = std::move(static_cast<std::thread&&>(std::move(m)));
//  }
  MetricsRunner() = default;
  MetricsRunner(std::thread && t)
    : t_(std::move(t)) {}
  MetricsRunner(MetricsRunner&&mr){
    *this = std::move(mr);
  }
  MetricsRunner&operator=(MetricsRunner&&mr){
    this->t_ = std::move(mr).t_;
    bool prev = mr.proceed_.test_and_set();
    if(prev) {
      this->proceed_.test_and_set();
    }else{
      this->proceed_.clear();
      mr.proceed_.clear();
    }
    return *this;
  }
  ~MetricsRunner(){ stop(); t_.join(); }
  void stop(){ proceed_.clear(); }
  bool is_proceed(){ return proceed_.test_and_set(); }
private:
  std::thread t_;
  std::atomic_flag proceed_ {true};
};

class Metrics {
  using OnProposalSubscription = iroha::BaseSubscriber<
      bool,iroha::network::OrderingEvent>;  //FixMe subscribtion ≠ subscriber
  using BlockPtr = std::shared_ptr<const shared_model::interface::Block>;
  using BlockSubscriber = iroha::BaseSubscriber<bool,BlockPtr>;

  std::string listen_addr_port_;
  std::shared_ptr<prometheus::Exposer> exposer_;
  std::shared_ptr<prometheus::Registry> registry_;
  std::shared_ptr<iroha::ametsuchi::Storage> storage_;
//  std::shared_ptr<iroha::ametsuchi::WsvQuery> wsv_;
  std::shared_ptr<BlockSubscriber> block_subscriber_;
  std::shared_ptr<OnProposalSubscription> on_proposal_subscription_;
  logger::LoggerPtr logger_;
//  MetricsRunner runner_;

 public:
  Metrics(
      std::string const& listen_addr,
      std::shared_ptr<iroha::ametsuchi::Storage> storage,
      logger::LoggerPtr const& logger
  );
  std::string const& getListenAddress()const{ return listen_addr_port_; }
  bool valid()const;
};

#endif //IROHA_MAINTENANCE_METRICS_HPP
