/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_connection_manager.hpp"

#include "common/result.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "logger/logger.hpp"
#include "ordering/impl/on_demand_common.hpp"

using namespace iroha;
using namespace iroha::ordering;

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    logger::LoggerPtr log)
    : log_(std::move(log)), factory_(std::move(factory)) {}

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    CurrentPeers initial_peers,
    logger::LoggerPtr log)
    : OnDemandConnectionManager(std::move(factory), std::move(log)) {
  initializeConnections(initial_peers);
}

OnDemandConnectionManager::~OnDemandConnectionManager() {
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
      if (auto &connection = connections_.peers[consumer]) {
        (*connection)->onBatches(batches);
      };
    }
  };

  propagate(kIssuer);
  propagate(kRejectConsumer);
  propagate(kCommitConsumer);
}

void OnDemandConnectionManager::onRequestProposal(consensus::Round round) {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  if (stop_requested_.load(std::memory_order_relaxed)) {
    return;
  }

  log_->debug("onRequestProposal, {}", round);

  if (auto &connection = connections_.peers[kIssuer]) {
    (*connection)->onRequestProposal(round);
  }
}

void OnDemandConnectionManager::initializeConnections(
    const CurrentPeers &peers) {
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
  if (stop_requested_.load(std::memory_order_relaxed)) {
    // Object was destroyed and `this' is no longer valid.
    return;
  }
  auto create_assign = [&](auto target) {
    auto maybe_connection = factory_->create(*peers.peers[target]);
    if (expected::hasError(maybe_connection)) {
      connections_.peers[target] = std::nullopt;
    }
    connections_.peers[target] = std::move(maybe_connection).assumeValue();
  };

  create_assign(kIssuer);
  create_assign(kRejectConsumer);
  create_assign(kCommitConsumer);
}
