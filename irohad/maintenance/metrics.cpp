/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "maintenance/metrics.hpp"

#include <prometheus/counter.h>
#include <prometheus/exposer.h>
#include <prometheus/registry.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <future>
#include <regex>

#include "validators/field_validator.hpp"

std::shared_ptr<prometheus::Registry> maintenance_metrics_init(std::string const& listen_addr)
{
  using namespace prometheus;

  shared_model::validation::FieldValidator validator;
  std::string listen_addr_port;
  if(not validator.validatePeerAddress(listen_addr)) {
    listen_addr_port = listen_addr;
  } else if(not validator.validatePort(listen_addr)) {
    listen_addr_port = "127.0.0.1";
    if (listen_addr[0] != ':')
      listen_addr_port += ":";
    listen_addr_port += listen_addr;
  } else {
    return nullptr;
  }

  // create a metrics registry
  // @note it's the users responsibility to keep the object alive
  auto registry = std::make_shared<Registry>();

  // Just for example
  std::thread([registry,listen_addr_port](){
      // create an http server running on addr:port
      Exposer exposer{listen_addr_port};

      // ask the exposer to scrape the registry on incoming HTTP requests
      exposer.RegisterCollectable(registry);

    // add a new counter family to the registry (families combine values with the
    // same name, but distinct label dimensions)
    //
    // @note please follow the metric-naming best-practices:
    // https://prometheus.io/docs/practices/naming/
    auto& packet_counter = BuildCounter()
        .Name("observed_packets_total")
        .Help("Number of observed packets")
        .Register(*registry);

    // add and remember dimensional data, incrementing those is very cheap
    auto& tcp_rx_counter =
        packet_counter.Add({{"protocol", "tcp"}, {"direction", "rx"}});
    auto& tcp_tx_counter =
        packet_counter.Add({{"protocol", "tcp"}, {"direction", "tx"}});
    auto& udp_rx_counter =
        packet_counter.Add({{"protocol", "udp"}, {"direction", "rx"}});
    auto& udp_tx_counter =
        packet_counter.Add({{"protocol", "udp"}, {"direction", "tx"}});

    // add a counter whose dimensional data is not known at compile time
    // nevertheless dimensional values should only occur in low cardinality:
    // https://prometheus.io/docs/practices/naming/#labels
    auto& http_requests_counter = BuildCounter()
        .Name("http_requests_total")
        .Help("Number of HTTP requests")
        .Register(*registry);

    for (;;) {
      std::this_thread::sleep_for(std::chrono::seconds(1));
      const auto random_value = std::rand();

      if (random_value & 1) tcp_rx_counter.Increment();
      if (random_value & 2) tcp_tx_counter.Increment();
      if (random_value & 4) udp_rx_counter.Increment();
      if (random_value & 8) udp_tx_counter.Increment();

      const std::array<std::string, 4> methods = {"GET", "PUT", "POST", "HEAD"};
      auto method = methods.at(random_value % methods.size());
      // dynamically calling Family<T>.Add() works but is slow and should be avoided
      http_requests_counter.Add({{"method", method}}).Increment();
    }
  }).detach();

  return {registry};
}
