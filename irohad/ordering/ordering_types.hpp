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

#define USE_BLOOM_FILTER 0

  static constexpr uint64_t kBloomFilterOrder = 256ull;
  static constexpr uint64_t kBloomFilterSize = kBloomFilterOrder / 8ull;

  using BloomFilter256 = shared_model::crypto::BloomFilter<
      shared_model::crypto::Hash,
      kBloomFilterOrder,
      shared_model::crypto::Iroha2BloomHasher64<0, kBloomFilterSize>,
      shared_model::crypto::Iroha2BloomHasher64<1, kBloomFilterSize>,
      shared_model::crypto::Iroha2BloomHasher64<2, kBloomFilterSize>,
      shared_model::crypto::Iroha2BloomHasher64<3, kBloomFilterSize>,
      shared_model::crypto::Iroha2BloomHasher64<4, kBloomFilterSize>,
      shared_model::crypto::Iroha2BloomHasher64<5, kBloomFilterSize>,
      shared_model::crypto::Iroha2BloomHasher64<6, kBloomFilterSize>>;

  struct RemoteProposalDownloadedEvent {
    std::shared_ptr<shared_model::interface::Proposal const> local;
    std::shared_ptr<shared_model::interface::Proposal const> remote;
    std::string bloom_filter;
    std::string remote_proposal_hash;
    consensus::Round round;
    shared_model::interface::types::TimestampType created_time;
  };

  /**
   * Type of stored proposals
   */
  using ProposalType = shared_model::interface::Proposal;
  using PackedProposalType =
      std::pair<std::shared_ptr<ProposalType const>, BloomFilter256>;

  using PackedProposalContainer = std::vector<PackedProposalType>;
  using PackedProposalData = std::optional<PackedProposalContainer>;

}  // namespace iroha::ordering

#endif  // IROHA_ORDERING_TYPES_HPP
