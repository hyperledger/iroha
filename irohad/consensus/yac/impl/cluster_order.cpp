/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/cluster_order.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      boost::optional<ClusterOrdering> ClusterOrdering::create(
          const std::vector<std::shared_ptr<shared_model::interface::Peer>>
              &order) {
        if (order.empty()) {
          return boost::none;
        }
        return ClusterOrdering(order);
      }

      ClusterOrdering::ClusterOrdering(
          std::vector<std::shared_ptr<shared_model::interface::Peer>> order)
          : order_(std::move(order)) {}

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

      const shared_model::interface::types::PeerList &
      ClusterOrdering::getPeers() const {
        return order_;
      }

      size_t ClusterOrdering::getNumberOfPeers() const {
        return order_.size();
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
