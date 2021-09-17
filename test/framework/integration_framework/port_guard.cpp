/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "framework/integration_framework/port_guard.hpp"

#include <boost/asio.hpp>
#include <boost/assert.hpp>
#include <boost/format.hpp>
#include <iostream>
#include <memory>

namespace integration_framework {

  constexpr PortGuard::PortType PortGuard::kMaxPort;
  PortGuard::UsedPorts PortGuard::all_used_ports_ = {};
  std::mutex PortGuard::all_used_ports_mutex_ = {};

  PortGuard::PortGuard() = default;

  PortGuard::PortGuard(PortGuard &&other) noexcept
      : instance_used_ports_(std::move(other.instance_used_ports_)) {
    other.instance_used_ports_.reset();
  }

  PortGuard::~PortGuard() {
    std::lock_guard<std::mutex> lock(all_used_ports_mutex_);
    BOOST_ASSERT_MSG(
        ((all_used_ports_ | instance_used_ports_) ^ all_used_ports_).none(),
        "Some ports used by this PortGuard instance are not set in ports "
        "used by all instances!");
    all_used_ports_ &= ~instance_used_ports_;
  }

  void PortGuard::unbind(PortType port) {
    size_t k = occupied_sockets_.erase(port);
    assert(k == 1);
  }
  bool PortGuard::is_bound(PortType port) {
    return occupied_sockets_.find(port) != occupied_sockets_.end();
  }

  std::optional<PortGuard::PortType> PortGuard::tryGetPort(
      PortType port, const PortType port_max) {
    using namespace boost::asio;
    using namespace boost::asio::ip;
    auto const port_min = port;
    std::lock_guard<std::mutex> lock(all_used_ports_mutex_);
    std::unique_ptr<tcp::acceptor> sock;
    auto endpoint = tcp::endpoint(make_address_v4("127.0.0.1"), port);
    for (; port <= port_max; ++port) {
      if (all_used_ports_.test(port))
        continue;
      try {
        endpoint.port(port);
        sock =
            std::unique_ptr<tcp::acceptor>(new tcp::acceptor(ioctx_, endpoint));
        break;
      } catch (std::exception const &ex) {
        std::cout << "tryOccupyPort: port=" << port << " error=" << ex.what()
                  << std::endl;
        continue;
      }
    }
    if (port >= port_max) {
      return std::nullopt;
    }
    BOOST_ASSERT_MSG(!all_used_ports_.test(port),
                     "PortGuard chose an occupied port!");
    BOOST_ASSERT_MSG(port >= port_min && port <= port_max,
                     "PortGuard chose a port outside boundaries!");
    instance_used_ports_.set(port);
    all_used_ports_.set(port);
    occupied_sockets_.emplace(port, std::move(sock));
    return port;
  }

  PortGuard::PortType PortGuard::getPort(PortType min, PortType max) {
    const auto opt_port = tryGetPort(min, max);
    BOOST_VERIFY_MSG(
        opt_port,
        (boost::format("Could not get a port in interval [%d, %d]!") % min
         % max)
            .str()
            .c_str());
    return *opt_port;
  }

}  // namespace integration_framework
