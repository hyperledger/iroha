/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/peer_orderer_impl.hpp"

#include <random>

#include "common/bind.hpp"
#include "common/permutation_generator.hpp"
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "interfaces/common_objects/peer.hpp"

using iroha::consensus::yac::PeerOrdererImpl;

std::optional<iroha::consensus::yac::ClusterOrdering>
PeerOrdererImpl::getOrdering(
    const YacHash &hash,
    std::vector<std::shared_ptr<shared_model::interface::Peer>> const &peers) {
  auto prng = iroha::makeSeededPrng(hash.vote_hashes.block_hash.data(),
                                    hash.vote_hashes.block_hash.size());
  iroha::generatePermutation(peer_positions_, std::move(prng), peers.size());

  return ClusterOrdering::create(peers, peer_positions_);
}
