/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_INTEGRATION_FRAMEWORK_PORT_GUARD_HPP
#define IROHA_INTEGRATION_FRAMEWORK_PORT_GUARD_HPP

#include <bitset>
#include <cstdint>
#include <mutex>

#include <boost/noncopyable.hpp>
#include <boost/optional/optional.hpp>

namespace integration_framework {

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
    std::optional<PortType> tryGetPort(PortType min_value,
                                         PortType max_value = kMaxPort);

   private:
    using UsedPorts = std::bitset<kMaxPort + 1>;

    static UsedPorts all_used_ports_;
    static std::mutex all_used_ports_mutex_;

    UsedPorts instance_used_ports_;
  };

}  // namespace integration_framework

#endif /* IROHA_INTEGRATION_FRAMEWORK_PORT_GUARD_HPP */
