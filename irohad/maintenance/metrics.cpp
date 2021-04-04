/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "maintenance/metrics.hpp"
#include "main/subscription.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "network/ordering_gate_common.hpp"

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <future>
#include <regex>

using namespace iroha;
using namespace prometheus;

bool Metrics::valid()const{
  return registry and exposer and block_subscriber and on_proposal_subscription_;
}

Metrics::Metrics(
    std::string const& listen_addr,
    shared_model::interface::types::HeightType block_height)
{
  static const std::regex full_matcher("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]):[0-9]+$");
  static const std::regex port_matcher("^:?([0-9]{1,5})$");
  std::string listen_addr_port;
  if(std::regex_match(listen_addr,full_matcher)) {
    listen_addr_port = listen_addr;
  } else if(std::regex_match(listen_addr,port_matcher)) {
    listen_addr_port = "127.0.0.1";
    if (listen_addr[0] != ':')
      listen_addr_port += ":";
    listen_addr_port += listen_addr;
  } else {
    return;
  }

  // create a metrics registry
  // @note it's the users responsibility to keep the object alive
  registry = std::make_shared<Registry>();

  // create an http server running on addr:port
  exposer = std::make_shared<Exposer>(listen_addr_port);

  // ask the exposer to scrape the registry on incoming HTTP requests
  exposer->RegisterCollectable(registry);

  auto&block_height_gauge = BuildGauge()
                                .Name("blocks_height")
                                .Help("Total number of blocks in chain")
                                //.Labels({{"label","a_metter"}})
                                .Register(*registry);
  auto&block_height_value = block_height_gauge.Add({});//{{"value", "some"}});
  block_height_value.Set(block_height);

  auto&peers_number_gauge = BuildGauge()
      .Name("peers_number")
      .Help("Total number peers to send transactions and request proposals")
      //.Labels({{"label","a_metter"}})
      .Register(*registry);
  auto&peers_number_value = peers_number_gauge.Add({});//{{"valueP", "any"}});

  block_subscriber = std::make_shared<BlockSubscriber>(
      getSubscription()->getEngine<EventTypes,BlockPtr>());
  block_subscriber->setCallback(
        [&block_height_value] //Stored in registry
        (auto, auto&receiver, auto const event, auto pblock){
          // block_height_value is captured by reference because it is stored inside registry, which is shared_ptr
          assert(!!pblock);
          block_height_value.Set(pblock->height());
        });
  block_subscriber->subscribe<SubscriptionEngineHandlers::kMetrics>(
      EventTypes::kOnBlock);

//  using CurrentPeers = ordering::OnDemandConnectionManager::CurrentPeers;
//  using PeersSubscriber = BaseSubscriber<bool, CurrentPeers>;
//  auto peers_subscriber = std::make_shared<PeersSubscriber>(
//        getSubscription()->getEngine<EventTypes, CurrentPeers>() );
//  peers_subscriber->setCallback([](auto, auto &, auto key, auto const &peers) {
//    assert(EventTypes::kOnCurrentRoundPeers == key);
//    peers.peers.
//  });
//  peers_subscriber->subscribe<SubscriptionEngineHandlers::kYac>(
//        0, EventTypes::kOnCurrentRoundPeers);

//  using OnProposalSubscription = BaseSubscriber<bool,network::OrderingEvent>;  //FixMe subscribtion ≠ subscriber
  on_proposal_subscription_ = std::make_shared<OnProposalSubscription>(
      getSubscription()->getEngine<EventTypes, network::OrderingEvent>());
  on_proposal_subscription_->setCallback(
      [&peers_number_value]
      (auto, auto, auto key, network::OrderingEvent const &oe) {
        // block_height_value can be captured by reference because it is stored inside registry
        assert(EventTypes::kOnProposal == key);
        peers_number_value.Set(oe.ledger_state->ledger_peers.size());
      });
  on_proposal_subscription_->subscribe<SubscriptionEngineHandlers::kMetrics>(
      EventTypes::kOnProposal);

//  // Just for example
//  MetricsRunner runner([registry,listen_addr_port](){
//    // add a new counter family to the registry (families combine values with the
//    // same name, but distinct label dimensions)
//    //
//    // @note please follow the metric-naming best-practices:
//    // https://prometheus.io/docs/practices/naming/
//    auto& packet_counter = BuildCounter()
//        .Name("observed_packets_total")
//        .Help("Number of observed packets")
//        .Register(*registry);
//
//    // add and remember dimensional data, incrementing those is very cheap
//    auto& tcp_rx_counter =
//        packet_counter.Add({{"protocol", "tcp"}, {"direction", "rx"}});
//    auto& tcp_tx_counter =
//        packet_counter.Add({{"protocol", "tcp"}, {"direction", "tx"}});
//    auto& udp_rx_counter =
//        packet_counter.Add({{"protocol", "udp"}, {"direction", "rx"}});
//    auto& udp_tx_counter =
//        packet_counter.Add({{"protocol", "udp"}, {"direction", "tx"}});
//
//    // add a counter whose dimensional data is not known at compile time
//    // nevertheless dimensional values should only occur in low cardinality:
//    // https://prometheus.io/docs/practices/naming/#labels
//    auto& http_requests_counter = BuildCounter()
//        .Name("http_requests_total")
//        .Help("Number of HTTP requests")
//        .Register(*registry);

//    for (;;) {
//      std::this_thread::sleep_for(std::chrono::seconds(1));
//      const auto random_value = std::rand();
//
//      if (random_value & 1) tcp_rx_counter.Increment();
//      if (random_value & 2) tcp_tx_counter.Increment();
//      if (random_value & 4) udp_rx_counter.Increment();
//      if (random_value & 8) udp_tx_counter.Increment();
//
//      const std::array<std::string, 4> methods = {"GET", "PUT", "POST", "HEAD"};
//      auto method = methods.at(random_value % methods.size());
//      // dynamically calling Family<T>.Add() works but is slow and should be avoided
//      http_requests_counter.Add({{"method", method}}).Increment();
//    }
//  });

//  return Metrics{ std::move(registry), std::move(exposer) };//, std::move(runner) };
}
