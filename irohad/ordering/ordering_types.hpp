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

  static constexpr uint64_t kBloomFilterOrder = 32 * 1024ull;
  using BloomFilter256 = shared_model::crypto::BloomFilter<
      shared_model::crypto::Hash,
      kBloomFilterOrder,
      shared_model::crypto::Iroha2BloomHasher64<0, kBloomFilterOrder / 8>,
      shared_model::crypto::Iroha2BloomHasher64<1, kBloomFilterOrder / 8>,
      shared_model::crypto::Iroha2BloomHasher64<2, kBloomFilterOrder / 8>,
      shared_model::crypto::Iroha2BloomHasher64<3, kBloomFilterOrder / 8>,
      shared_model::crypto::Iroha2BloomHasher64<4, kBloomFilterOrder / 8>,
      shared_model::crypto::Iroha2BloomHasher64<5, kBloomFilterOrder / 8>,
      shared_model::crypto::Iroha2BloomHasher64<6, kBloomFilterOrder / 8>/*,
      shared_model::crypto::Iroha2BloomHasher64<7, kBloomFilterOrder / 8>*/>;

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
