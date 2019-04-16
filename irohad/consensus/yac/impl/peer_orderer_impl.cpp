/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/peer_orderer_impl.hpp"

#include <random>

#include "common/bind.hpp"
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "interfaces/common_objects/peer.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {
      PeerOrdererImpl::PeerOrdererImpl(
          std::shared_ptr<ametsuchi::PeerQueryFactory> peer_query_factory)
          : peer_query_factory_(peer_query_factory) {}

      boost::optional<ClusterOrdering> PeerOrdererImpl::getOrdering(
          const YacHash &hash,
          std::vector<std::shared_ptr<shared_model::interface::Peer>> peers) {
        std::seed_seq seed(hash.vote_hashes.block_hash.begin(),
                           hash.vote_hashes.block_hash.end());
        std::default_random_engine gen(seed);
        std::shuffle(peers.begin(), peers.end(), gen);
        return ClusterOrdering::create(peers);
      }
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
