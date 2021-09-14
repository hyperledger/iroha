/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_INTEGRATION_FRAMEWORK_PORT_GUARD_HPP
#define IROHA_INTEGRATION_FRAMEWORK_PORT_GUARD_HPP

#include <bitset>
#include <boost/asio/ip/tcp.hpp>
#include <boost/noncopyable.hpp>
#include <boost/optional/optional.hpp>
#include <cstdint>
#include <mutex>

namespace integration_framework {

  /// return socket to keep it bound, then may destroy or better reuse
  struct NextAvailablePort {
    uint16_t port = 0;
    std::unique_ptr<boost::asio::ip::tcp::acceptor> psock;
  };
  NextAvailablePort getNextAvailablePort(uint16_t port,
                                         uint16_t portmax = 0,
                                         std::string_view addr = "127.0.0.1");

  /**
   * A trivial port manager that guarantees no instances will get two equal port
   * values. It keeps track of ports handed out bo all instances and reuses them
   * when these die.
   */
  class PortGuard final : public boost::noncopyable {
   public:
    using PortType = uint16_t;

    static constexpr PortType kMaxPort = 65535;

    PortGuard();
    PortGuard(PortGuard &&other) noexcept;

    // Just not implemented.
    PortGuard &operator=(PortGuard &&other) = delete;

    ~PortGuard();

    /// Request a port in given boundaries, including them. Aborts if
    /// all ports within the range are in use.
    PortType getPort(PortType min_value, PortType max_value = kMaxPort);

    /// Request a port in given boundaries, including them.
    boost::optional<PortType> tryGetPort(PortType min_value,
                                         PortType max_value = kMaxPort);

    size_t count_busy() const {
      return all_used_ports_.count();
    }

   private:
    using UsedPorts = std::bitset<kMaxPort + 1>;

    static UsedPorts all_used_ports_;
    static std::mutex all_used_ports_mutex_;

    UsedPorts instance_used_ports_;
  };

}  // namespace integration_framework

#endif /* IROHA_INTEGRATION_FRAMEWORK_PORT_GUARD_HPP */
