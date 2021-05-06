/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_connection_manager.hpp"

#include <boost/range/combine.hpp>
#include "common/bind.hpp"
#include "common/result.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "logger/logger.hpp"
#include "ordering/impl/on_demand_common.hpp"

using namespace iroha;
using namespace iroha::ordering;

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    rxcpp::observable<CurrentPeers> peers,
    logger::LoggerPtr log)
    : log_(std::move(log)),
      factory_(std::move(factory)),
      subscription_(peers.subscribe([this](const auto &peers) {
        // `this' is captured raw and needs protection during destruction of
        // OnDemandConnectionManager. We assert that
        // OnDemandConnectionManager::initializeConnections locks the mutex and
        // does not use `this' if stop_requested_ reads `true'.
        this->initializeConnections(peers);
      })) {}

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    rxcpp::observable<CurrentPeers> peers,
    CurrentPeers initial_peers,
    logger::LoggerPtr log)
    : OnDemandConnectionManager(std::move(factory), peers, std::move(log)) {
  // using start_with(initial_peers) results in deadlock
  initializeConnections(initial_peers);
}

OnDemandConnectionManager::~OnDemandConnectionManager() {
  subscription_.unsubscribe();
  stop_requested_.store(true);
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
}

void OnDemandConnectionManager::onBatches(CollectionType batches) {
  /*
   * Transactions are sent to the current and next rounds (+1)
   * There are 3 possibilities. This can be visualised as a diagram,
   * where: o - current round, x - next round
   *
   *    0 1         0 1         0 1
   *  0 o .       0 o x       0 o .
   *  1 . .       1 . .       1 x .
   * Issuer      Reject      Commit
   */

  auto propagate = [&](auto consumer) {
    std::shared_lock<std::shared_timed_mutex> lock(mutex_);
    if (not stop_requested_.load(std::memory_order_relaxed)) {
      connections_.peers[consumer] | [&batches](const auto &connection) {
        connection->onBatches(batches);
      };
    }
  };

  propagate(kIssuer);
  propagate(kRejectConsumer);
  propagate(kCommitConsumer);
}

boost::optional<std::shared_ptr<const OnDemandConnectionManager::ProposalType>>
OnDemandConnectionManager::onRequestProposal(consensus::Round round) {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  if (stop_requested_.load(std::memory_order_relaxed)) {
    return boost::none;
  }

  log_->debug("onRequestProposal, {}", round);

  return connections_.peers[kIssuer] | [&round](const auto &connection) {
    return connection->onRequestProposal(round);
  };
}

void OnDemandConnectionManager::initializeConnections(
    const CurrentPeers &peers) {
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
  if (stop_requested_.load(std::memory_order_relaxed)) {
    // Object was destroyed and `this' is no longer valid.
    return;
  }
  auto create_assign = [this](auto &connection, auto &peer) {
    connection = expected::resultToOptionalValue(factory_->create(*peer));
  };

  for (auto &&pair : boost::combine(connections_.peers, peers.peers)) {
    create_assign(boost::get<0>(pair), boost::get<1>(pair));
  }
}
