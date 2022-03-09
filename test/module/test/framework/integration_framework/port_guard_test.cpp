/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <thread>

#include <gtest/gtest.h>
#include <boost/noncopyable.hpp>
#include <boost/thread/barrier.hpp>
#include "framework/integration_framework/port_guard.hpp"

using PortGuard = integration_framework::PortGuard;
using PortRange = std::pair<size_t, size_t>;

struct Client : boost::noncopyable {
  Client(){};
  Client(Client &&other)
      : port_guard(std::move(other.port_guard)),
        used_ports(std::move(other.used_ports)){};

  PortGuard port_guard;
  std::bitset<PortGuard::kMaxPort + 1> used_ports;
};

/// Start the given amount of client threads and wait till they complete.
void AddClients(std::vector<Client> &clients,
                size_t num_added,
                PortRange port_range) {
  boost::barrier bar(num_added);
  auto port_requester =
      [&bar, &clients, &port_range](const size_t client_number) {
        Client &client = clients[client_number];
        bar.wait();
        while (true) {
          auto port =
              client.port_guard.tryGetPort(port_range.first, port_range.second);
          if (!port) {
            break;
          }
          client.used_ports.set(*port);
        }
      };

  clients.reserve(clients.size() + num_added);
  std::vector<std::thread> threads;
  threads.reserve(num_added);
  for (size_t client_number = 0; client_number < num_added; ++client_number) {
    clients.emplace_back();
    threads.emplace_back(port_requester, clients.size() - 1);
  }

  // wait for the threads to complete
  for (auto &thread : threads) {
    thread.join();
  }
}

/// Check that all the ports in the interval are taken and none intersect.
void CheckPorts(std::vector<Client> &clients, PortRange port_range) {
  std::bitset<PortGuard::kMaxPort + 1> all_used_ports;
  for (auto &client : clients) {
    EXPECT_TRUE((all_used_ports & client.used_ports).none())
        << "Some ports were used by more than one client!";
    all_used_ports |= client.used_ports;
  }
  for (size_t port = port_range.first; port <= port_range.second; ++port) {
    EXPECT_TRUE(all_used_ports.test(port))
        << "Port " << port << " was not given out to any client!";
  }
}

/**
 * @given a number a port consumers
 * @when they simultaneously try to get all the ports from the same range
 * @then all the ports from the range are distributed among them with no
 * overlaps
 */
TEST(PortGuardTest, AllPortsGetUsedAndNoOverlaps) {
  GTEST_SKIP();
  constexpr size_t kNumClients = 10;
  constexpr PortRange kRange = {123, 456};

  std::vector<Client> clients;
  AddClients(clients, kNumClients, kRange);
  CheckPorts(clients, kRange);
}

/**
 * @given a number a port consumers with allocated ports
 * @when some of them are destroyed and some new are created, that try to get
 * all the ports from the same range
 * @then all the ports from the range are distributed among them with no
 * overlaps
 */
TEST(PortGuardTest, AllPortsGetUsedAndNoOverlapsAfterRestart) {
  GTEST_SKIP();
  constexpr size_t kNumClients = 10;            // first-run clients
  constexpr size_t kNumClientsKilled = 3;       // then these die
  constexpr size_t kNumClientsResurrected = 5;  // then these are added
  constexpr PortRange kRange = {123, 456};

  std::vector<Client> clients;

  // add some clients
  AddClients(clients, kNumClients, kRange);

  // kill some clients
  clients.resize(kNumClients - kNumClientsKilled);

  // run some new clients
  AddClients(clients, kNumClientsResurrected, kRange);
  CheckPorts(clients, kRange);
}
