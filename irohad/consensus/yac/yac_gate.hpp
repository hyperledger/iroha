/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_GATE_HPP
#define IROHA_YAC_GATE_HPP

#include <optional>

#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/storage/storage_result.hpp"
#include "network/consensus_gate.hpp"

namespace iroha::consensus {
  struct Round;
}

namespace iroha::consensus::yac {
  class YacHash;
  class ClusterOrdering;

  class YacGate : public network::ConsensusGate {};

  /**
   * Provide gate for ya consensus
   */
  class HashGate {
   public:
    /**
     * Proposal new hash in network
     * @param hash - hash for voting
     * @param order - peer ordering for round in hash
     * @param alternative_order - peer order
     */
    virtual void vote(
        YacHash hash,
        ClusterOrdering order,
        std::optional<ClusterOrdering> alternative_order = std::nullopt) = 0;

    /**
     * Update current state with the new round and peer list, possibly pruning
     * the old state. Process states from future if available, and return the
     * result
     * @param round - new round
     * @param peers - new peer list
     * @return answer if storage already contains required votes
     */
    virtual std::optional<Answer> processRoundSwitch(
        consensus::Round const &round,
        shared_model::interface::types::PeerList const &peers,
        shared_model::interface::types::PeerList const &sync_peers) = 0;

    /// Prevent any new outgoing network activity. Be passive.
    virtual void stop() = 0;

    virtual ~HashGate() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_GATE_HPP
