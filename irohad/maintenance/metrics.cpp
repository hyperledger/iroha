/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "maintenance/metrics.hpp"
#include "main/subscription.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "network/ordering_gate_common.hpp"
#include "interfaces/transaction.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/create_domain.hpp"

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>
#include <prometheus/gateway.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <future>
#include <regex>

#include <boost/asio.hpp>

using namespace iroha;
using namespace prometheus;
using namespace std::chrono_literals;

#include <iostream>
using std::endl, std::cerr;

static logger::LoggerPtr MetricsLogger;

// struct MetricsRunner {//: std::thread {
// //  using std::thread::thread;  // Does not inherit move ctor?
// ////  using std::thread::operator=;
// //  MetricsRunner(MetricsRunner&&m)noexcept
// //      : std::thread(std::move(m))
// ////      , proceed_(std::move(std::move(m).proceed_))
// //  {}
// //  MetricsRunner& operator=(MetricsRunner&&m)noexcept{
// //    return *this = std::move(static_cast<std::thread&&>(std::move(m)));
// //  }
//   MetricsRunner() = default;
//   MetricsRunner(std::thread && t)
//       : t_(std::move(t)) {}
//   MetricsRunner(MetricsRunner&&mr){
//     *this = std::move(mr);
//   }
//   MetricsRunner&operator=(MetricsRunner&&mr){
//     this->t_ = std::move(mr).t_;
//     bool prev = mr.proceed_.test_and_set();
//     if(prev) {
//       this->proceed_.test_and_set();
//     }else{
//       this->proceed_.clear();
//       mr.proceed_.clear();
//     }
//     return *this;
//   }
//    template<class...Args> MetricsRunner(Args&&...args)
//      :t_(std::forward<Args>(args)...)
//    {}
//   ~MetricsRunner(){ stop(); t_.join(); }
//   void stop(){ proceed_.clear(); }
//   bool is_proceed(){ return proceed_.test_and_set(); }
//  private:
//   std::thread t_;
//   std::atomic_flag proceed_ {true};
// };

/// Starts a thread with io_context, stops and joins on destruction
///@note it may take a time before posted task returns.
struct io_worker {
  std::thread thread_;
  boost::asio::io_context ioctx_;
  boost::asio::executor_work_guard<boost::asio::io_context::executor_type> guard_;
  std::vector<std::function<void(void)>> jobs_;

  io_worker()
      : guard_(boost::asio::make_work_guard(ioctx_))
  {
    thread_ = std::thread([this]{
      try {
        ioctx_.run();
      }catch(std::exception const& ex){
        assert(MetricsLogger);
        MetricsLogger->error("Error in metrics.cpp:io_worker:ioctx_.run(): {}",ex.what());
      }
    });
  }
  io_worker(io_worker const&) = delete;
  io_worker(io_worker&&) = delete;
  ~io_worker(){
    guard_.reset(); // stop io_context execution
    if(thread_.joinable())
        thread_.join();
  }

  std::vector<boost::asio::steady_timer> periodical_timers_;
  std::vector<std::function<void(const boost::system::error_code &)>> periodical_callbacks_;

  template <class F, class T>
  void run_periodical(F &&f, T &&period) {
    //todo static_assert(chrono::is_duration<T>);
    using boost::asio::steady_timer;
    periodical_timers_.push_back(steady_timer(this->ioctx_));
    periodical_callbacks_.push_back({});
    periodical_callbacks_.back() =
        [   f = std::forward<F>(f),
            period = std::forward<T>(period),
            &tim = periodical_timers_.back(),
            &tick = periodical_callbacks_.back()
        ](const boost::system::error_code &ec)mutable{
          f(ec);
          tim.expires_after(period);
          tim.async_wait(tick);
        };
    periodical_timers_.back().async_wait(periodical_callbacks_.back());
  }
};


static std::string GetHostName() {
  char hostname[1024];

  if (::gethostname(hostname, sizeof(hostname))) {
    return {};
  }
  return hostname;
}

bool Metrics::valid()const{
  return registry_ and exposer_ and block_subscriber_
      and on_proposal_subscription_ and storage_;
}

Metrics::Metrics(
    std::string const& listen_addr,
    std::string const& push_addr,
    std::shared_ptr<iroha::ametsuchi::Storage> storage,
    logger::LoggerPtr const& logger
    )
:storage_(storage),logger_(logger)
{
  static const std::regex full_matcher("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+$");
  static const std::regex port_matcher("^:?([0-9]{1,5})$");
  if(std::regex_match(listen_addr,full_matcher)) {
    listen_addr_port_ = listen_addr;
  } else if(std::regex_match(listen_addr,port_matcher)) {
    listen_addr_port_ = "127.0.0.1";
    if (listen_addr[0] != ':')
      listen_addr_port_ += ":";
    listen_addr_port_ += listen_addr;
  } else {
    return;
  }

  MetricsLogger = logger;

  // @note it's the users responsibility to keep the object alive
  registry_ = std::make_shared<Registry>();

  // create an http server running on addr:port
  exposer_ = std::make_shared<Exposer>(listen_addr_port_);

  // ask the exposer_ to scrape the registry_ on incoming HTTP requests
  exposer_->RegisterCollectable(registry_);

  auto&block_height_gauge = BuildGauge()
                                .Name("blocks_height")
                                .Help("Total number of blocks in chain")
                                //.Labels({{"label","a_metter"}})
                                .Register(*registry_);
  auto&block_height_value = block_height_gauge.Add({});//{{"value", "some"}});
  block_height_value.Set(storage_->getBlockQuery()->getTopBlockHeight());

  auto&peers_number_gauge = BuildGauge()
      .Name("peers_number")
      .Help("Total number peers to send transactions and request proposals")
      //.Labels({{"label","a_metter"}})
      .Register(*registry_);
  auto&peers_number_value = peers_number_gauge.Add({});//{{"valueP", "any"}});

  auto&domains_number_gauge = BuildGauge()
      .Name("number_of_domains")
      .Help("Total number of domains in WSV")
      //.Labels({{"label","a_metter"}})
      .Register(*registry_);
  auto&domains_number_value = domains_number_gauge.Add({});//{{"valueP", "any"}});

  block_subscriber_ = std::make_shared<BlockSubscriber>(
      getSubscription()->getEngine<EventTypes,BlockPtr>());
  block_subscriber_->setCallback(
        [&block_height_value,&domains_number_value] //Values are stored in registry_
        (auto, auto&receiver, auto const event, auto pblock){
          // block_height_value is captured by reference because it is stored inside registry_, which is shared_ptr
          assert(!!pblock);
          block_height_value.Set(pblock->height());
          //---
          int domain_created = 0;
          for(auto const& trx : pblock->transactions()){
            for(auto const& cmd : trx.commands()){
              using shared_model::interface::CreateDomain;
              domain_created += boost::get<CreateDomain>(&cmd.get()) != nullptr;
              //todo domains_removed += boost::get<RemoveDomain>(&cmd.get()) != nullptr;
            }
          }
          domains_number_value.Increment(domain_created);
          //if(domain_created){
          //  assert(storage_);
          //  assert(storage_->getWsvQuery());
          //  auto opt_n_domains = storage_->getWsvQuery()->getNumberOfDomains();
          //  if(opt_n_domains)
          //    domains_number_value.Set(*opt_n_domains);
          //  else
          //    logger_->warn("Cannot getNumberOfDomains() from WSV");
          //}
        });
  block_subscriber_->subscribe<SubscriptionEngineHandlers::kMetrics>(
      EventTypes::kOnBlock);
  
  on_proposal_subscription_ = std::make_shared<OnProposalSubscription>(
      getSubscription()->getEngine<EventTypes, network::OrderingEvent>());
  on_proposal_subscription_->setCallback(
      [&peers_number_value]
      (auto, auto, auto key, network::OrderingEvent const &oe) {
        // block_height_value can be captured by reference because it is stored inside registry_
        assert(EventTypes::kOnProposal == key);
        peers_number_value.Set(oe.ledger_state->ledger_peers.size());
      });
  on_proposal_subscription_->subscribe<SubscriptionEngineHandlers::kMetrics>(
      EventTypes::kOnProposal);

  // PUSH
  if(std::regex_match(push_addr,full_matcher)) {
    auto pos = push_addr.find(":");
    push_addr_ = std::string(push_addr,0,pos);
    push_port_ = std::string(push_addr,pos+1);
  } else if(std::regex_match(push_addr,port_matcher)) {
    push_addr_ = "127.0.0.1";
    if (push_addr[0] != ':')
      push_port_ = push_addr;
    else
      push_port_ = std::string(push_addr.begin()+1, push_addr.end());
  }
  if(push_addr_.size() and push_port_.size()) {
    // create a push gateway
    const auto labels = Gateway::GetInstanceLabel(GetHostName());
    gateway_ = std::make_shared<Gateway>(
        push_addr_, push_port_, "iroha_metrics_client", labels);  //todo label with node name and node public key
    // ask the pusher to push the metrics to the pushgateway
    gateway_->RegisterCollectable(registry_);

    io_worker_ =
        std::make_shared<io_worker>();  // starts a thread with io_context,
                                        // stops and joins on destruction,
                                        // handles thrown exceptions
    io_worker_->run_periodical(
        [&](const boost::system::error_code &ec) {
          // todo update registry if required before push
          std::cerr << "--------- gateway_ push" << std::endl;
          gateway_->Push();
        },
        5s);
  }
}
