/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/cluster_order.hpp"

#include <boost/assert.hpp>

using iroha::consensus::yac::ClusterOrdering;

std::optional<ClusterOrdering> ClusterOrdering::create(
    const std::vector<std::shared_ptr<shared_model::interface::Peer>> &order,
    std::vector<size_t> const &peer_positions) {
  if (order.empty()) {
    return std::nullopt;
  }
  return ClusterOrdering(order, peer_positions);
}

std::optional<ClusterOrdering> ClusterOrdering::create(
    const std::vector<std::shared_ptr<shared_model::interface::Peer>> &order) {
  if (order.empty()) {
    return std::nullopt;
  }
  return ClusterOrdering(order);
}

ClusterOrdering::ClusterOrdering(
    std::vector<std::shared_ptr<shared_model::interface::Peer>> const &order,
    std::vector<size_t> const &peer_positions) {
  order_.reserve(order.size());
  BOOST_ASSERT_MSG(peer_positions.size() == order.size(),
                   "Peer positions must be the same size to define ordering.");

  for (auto const &i : peer_positions) {
    order_.emplace_back(order[i]);
  }
}

ClusterOrdering::ClusterOrdering(
    std::vector<std::shared_ptr<shared_model::interface::Peer>> const &order)
    : order_(order) {}

// TODO :  24/03/2018 x3medima17: make it const, IR-1164
const shared_model::interface::Peer &ClusterOrdering::currentLeader() {
  if (index_ >= order_.size()) {
    index_ = 0;
  }
  return *order_.at(index_);
}

bool ClusterOrdering::hasNext() const {
  return index_ != order_.size();
}

ClusterOrdering &ClusterOrdering::switchToNext() {
  ++index_;
  return *this;
}

const shared_model::interface::types::PeerList &ClusterOrdering::getPeers()
    const {
  return order_;
}

size_t ClusterOrdering::getNumberOfPeers() const {
  return order_.size();
}
