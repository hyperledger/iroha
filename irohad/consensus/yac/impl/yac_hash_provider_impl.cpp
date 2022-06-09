/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_hash_provider_impl.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/iroha_internal/proposal.hpp"

using iroha::consensus::yac::YacHashProviderImpl;

iroha::consensus::yac::YacHash YacHashProviderImpl::makeHash(
    const simulator::BlockCreatorEvent &event) const {
  YacHash result(event.round);

  for (auto const &round_data : event.round_data) {
    auto &hash_data = result.appendHashes(round_data.proposal->hash().hex(),
                        round_data.block->hash().hex());
    hash_data.block_signature = clone(round_data.block->signatures().front());
  }
  return result;
}

shared_model::interface::types::HashType YacHashProviderImpl::toModelHash(
    const YacHash &hash, size_t index) const {
  assert(index < hash.vote_hashes.size());
  auto blob =
      shared_model::crypto::Blob::fromHexString(hash.vote_hashes[index].block_hash);
  auto string_blob = shared_model::crypto::toBinaryString(blob);
  return shared_model::interface::types::HashType(string_blob);
}
