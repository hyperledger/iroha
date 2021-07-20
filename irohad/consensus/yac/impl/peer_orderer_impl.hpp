/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_ORDERER_IMPL_HPP
#define IROHA_PEER_ORDERER_IMPL_HPP

#include <memory>

#include "consensus/yac/yac_peer_orderer.hpp"

namespace iroha::consensus::yac {
  class ClusterOrdering;
  class YacHash;

  class PeerOrdererImpl : public YacPeerOrderer {
   public:
    std::optional<ClusterOrdering> getOrdering(
        const YacHash &hash,
        std::vector<std::shared_ptr<shared_model::interface::Peer>> const
            &peers) override;

   private:
    std::vector<size_t> peer_positions_;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_PEER_ORDERER_IMPL_HPP
