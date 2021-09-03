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
  YacHash result;
  if (event.round_data) {
    result.vote_hashes.proposal_hash = event.round_data->proposal->hash().hex();
    result.vote_hashes.block_hash = event.round_data->block->hash().hex();
    result.block_signature =
        clone(event.round_data->block->signatures().front());
  }
  result.vote_round = event.round;

  return result;
}

shared_model::interface::types::HashType YacHashProviderImpl::toModelHash(
    const YacHash &hash) const {
  auto blob =
      shared_model::crypto::Blob::fromHexString(hash.vote_hashes.block_hash);
  auto string_blob = shared_model::crypto::toBinaryString(blob);
  return shared_model::interface::types::HashType(string_blob);
}
