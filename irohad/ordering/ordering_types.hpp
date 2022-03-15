/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_TYPES_HPP
#define IROHA_ORDERING_TYPES_HPP

#include "consensus/round.hpp"
#include "crypto/bloom.hpp"
#include "interfaces/iroha_internal/proposal.hpp"

namespace iroha::ordering {

  using BloomFilter256 = shared_model::crypto::BloomFilter<
      shared_model::crypto::Hash,
      256,
      shared_model::crypto::Iroha2BloomHasher64<0, 32>,
      shared_model::crypto::Iroha2BloomHasher64<1, 32>,
      shared_model::crypto::Iroha2BloomHasher64<2, 32>,
      shared_model::crypto::Iroha2BloomHasher64<3, 32>>;

  struct RemoteProposalDownloadedEvent {
    std::shared_ptr<shared_model::interface::Proposal const> local;
    std::shared_ptr<shared_model::interface::Proposal const> remote;
    std::string bloom_filter;
    std::string remote_proposal_hash;
    consensus::Round round;
    shared_model::interface::types::TimestampType created_time;
  };

}  // namespace iroha::ordering

#endif  // IROHA_ORDERING_TYPES_HPP
