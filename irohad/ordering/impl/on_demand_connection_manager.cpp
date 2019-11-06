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
      subscription_(peers.subscribe(
          [this](const auto &peers) { this->initializeConnections(peers); })) {}

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
}

void OnDemandConnectionManager::onBatches(CollectionType batches) {
  /*
   * Transactions are always sent to the round after the next round (+2)
   * There are 4 possibilities - all combinations of commits and rejects in the
   * following two rounds. This can be visualised as a diagram, where: o -
   * current round, x - next round, v - target round
   *
   *    0 1 2         0 1 2         0 1 2         0 1 2
   *  0 o x v       0 o . .       0 o x .       0 o . .
   *  1 . . .       1 x v .       1 v . .       1 x . .
   *  2 . . .       2 . . .       2 . . .       2 v . .
   * RejectReject  CommitReject  RejectCommit  CommitCommit
   */

  auto propagate = [&](auto consumer) {
    std::shared_lock<std::shared_timed_mutex> lock(mutex_);
    connections_.peers[consumer] |
        [&batches](const auto &connection) { connection->onBatches(batches); };
  };

  propagate(kRejectRejectConsumer);
  propagate(kRejectCommitConsumer);
  propagate(kCommitRejectConsumer);
  propagate(kCommitCommitConsumer);
}

boost::optional<std::shared_ptr<const OnDemandConnectionManager::ProposalType>>
OnDemandConnectionManager::onRequestProposal(consensus::Round round) {
  std::shared_lock<std::shared_timed_mutex> lock(mutex_);

  log_->debug("onRequestProposal, {}", round);

  return connections_.peers[kIssuer] | [&round](const auto &connection) {
    return connection->onRequestProposal(round);
  };
}

void OnDemandConnectionManager::initializeConnections(
    const CurrentPeers &peers) {
  auto create_assign = [this](auto &connection, auto &peer) {
    std::lock_guard<std::shared_timed_mutex> lock(mutex_);
    connection = expected::resultToOptionalValue(factory_->create(*peer));
  };

  for (auto &&pair : boost::combine(connections_.peers, peers.peers)) {
    create_assign(boost::get<0>(pair), boost::get<1>(pair));
  }
}
