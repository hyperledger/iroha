/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_connection_manager.hpp"

#include "common/result.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "logger/logger.hpp"
#include "ordering/impl/on_demand_common.hpp"
#include "interfaces/common_objects/peer.hpp"

using namespace iroha;
using namespace iroha::ordering;

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    logger::LoggerPtr log)
    : log_(std::move(log)), factory_(std::move(factory)) {}

OnDemandConnectionManager::OnDemandConnectionManager(
    std::shared_ptr<transport::OdOsNotificationFactory> factory,
    CurrentPeers initial_peers,
    shared_model::interface::types::PeerList const &all_peers,
    logger::LoggerPtr log)
    : OnDemandConnectionManager(std::move(factory), std::move(log)) {
  initializeConnections(initial_peers, all_peers);
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

void OnDemandConnectionManager::onBatchesToWholeNetwork(CollectionType batches) {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);
  if (not stop_requested_.load(std::memory_order_relaxed))
    for (auto &connection : connections_.all_connections)
      (*connection)->onBatches(batches);
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
    const CurrentPeers &peers, shared_model::interface::types::PeerList const &all_peers) {
  std::lock_guard<std::shared_timed_mutex> lock(mutex_);
  if (stop_requested_.load(std::memory_order_relaxed)) {
    // Object was destroyed and `this' is no longer valid.
    return;
  }

  connections_.all_connections.clear();
  for (auto &p : all_peers) {
    if (auto maybe_connection = factory_->create(*p);
        expected::hasValue(maybe_connection))
      connections_.all_connections.emplace_back(
          std::move(maybe_connection).assumeValue());
    else
      connections_.all_connections.emplace_back(std::nullopt);
  }

  auto create_assign = [&](auto target) {
    for (size_t ix = 0; ix < all_peers.size(); ++ix)
      if (all_peers[ix]->address() == peers.peers[target]->address() && all_peers[ix]->pubkey() == peers.peers[target]->pubkey())
        connections_.peers[target] = connections_.all_connections[ix];
  };

  create_assign(kIssuer);
  create_assign(kRejectConsumer);
  create_assign(kCommitConsumer);
}
