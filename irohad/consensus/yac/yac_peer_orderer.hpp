/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_PEER_ORDERER_HPP
#define IROHA_YAC_PEER_ORDERER_HPP

#include <optional>

#include "consensus/yac/cluster_order.hpp"

namespace iroha::consensus::yac {
  class YacHash;

  /**
   * Interface responsible for creating order for yac consensus
   */
  class YacPeerOrderer {
   public:
    /**
     * Provide order of peers based on hash and initial order of peers
     * @param hash - hash-object that used as seed of ordering shuffle
     * @param peers - an ordered list of peers
     * @return shuffled cluster order
     */
    virtual std::optional<ClusterOrdering> getOrdering(
        const YacHash &hash,
        std::vector<std::shared_ptr<shared_model::interface::Peer>> const
            &peers) = 0;

    virtual ~YacPeerOrderer() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_PEER_ORDERER_HPP
