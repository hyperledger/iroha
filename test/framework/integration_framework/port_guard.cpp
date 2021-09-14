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
  /// return socket to keep it bound, then may destroy or better reuse
  NextAvailablePort getNextAvailablePort(uint16_t port,
                                         uint16_t portmax,
                                         std::string_view addr) {
    //    try {
    portmax = portmax ? portmax : port + 1000;
    using namespace boost::asio;
    using namespace boost::asio::ip;
    io_context ioctx;
    boost::system::error_code err;
    // sock.set_option(socket_base::reuse_address(true));
    auto endpoint = tcp::endpoint(make_address_v4(addr), port);
    for (; port <= portmax; ++port) {
      endpoint.port(port);
      // sock->bind(endpoint, err);
      auto acp = std::unique_ptr<tcp::acceptor>(new tcp::acceptor(ioctx));
      if (!err)
        return {port, std::move(acp)};
      std::cout << "getNextAvailablePort: port=" << port << " error=" << err
                << " " << err.message() << std::endl;
    }
    //    } catch (std::exception) {
    //    }
    return {};
  }

  NextAvailablePort tryOccupyPort(uint16_t port,
                                  std::string_view addr = "127.0.0.1") {
    using namespace boost::asio;
    using namespace boost::asio::ip;
    io_context ioctx;
    boost::system::error_code err;
    auto endpoint = tcp::endpoint(make_address_v4(addr), port);
    auto acp = std::unique_ptr<tcp::acceptor>(new tcp::acceptor(ioctx));
    if (!err)
      return {port, std::move(acp)};
    std::cout << "tryOccupyPort: port=" << port << " error=" << err
              << " " << err.message() << std::endl;
    return {};
  }

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

  boost::optional<PortGuard::PortType> PortGuard::tryGetPort(
      const PortType min_value, const PortType max_value) {
    std::lock_guard<std::mutex> lock(all_used_ports_mutex_);
    NextAvailablePort nap;
    auto tested_port = min_value;
    while (all_used_ports_.test(tested_port)
    or (nap = tryOccupyPort(tested_port)).port == 0) {
      if (tested_port == max_value) {
        return boost::none;
      }
      ++tested_port;
    }
    BOOST_ASSERT_MSG(!all_used_ports_.test(tested_port),
                     "PortGuard chose an occupied port!");
    BOOST_ASSERT_MSG(tested_port >= min_value && tested_port <= max_value,
                     "PortGuard chose a port outside boundaries!");
    instance_used_ports_.set(tested_port);
    all_used_ports_.set(tested_port);
    //todo keep sockets, then reuse them when run server:
    //todo occupied_sockets_.emplace_back(std::move(nap.psock));
    return tested_port;
  }

  PortGuard::PortType PortGuard::getPort(const PortType min_value,
                                         const PortType max_value) {
    const auto opt_port = tryGetPort(min_value, max_value);
    BOOST_VERIFY_MSG(
        opt_port,
        (boost::format("Could not get a port in interval [%d, %d]!") % min_value
         % max_value)
            .str()
            .c_str());
    return *opt_port;
  }

}  // namespace integration_framework
