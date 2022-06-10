/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_HASH_PROVIDER_HPP
#define IROHA_YAC_HASH_PROVIDER_HPP

#include <ciso646>
#include <memory>
#include <string>

#include "consensus/round.hpp"
#include "consensus/yac/storage/yac_common.hpp"
#include "interfaces/common_objects/types.hpp"
#include "simulator/block_creator_common.hpp"
#include "utils/string_builder.hpp"

namespace shared_model::interface {
  class Signature;
  class Block;
}  // namespace shared_model::interface

namespace iroha::consensus::yac {
  class YacHash {
   public:
    // TODO: 2019-02-08 @muratovv IR-288 refactor YacHash: default ctor,
    // block signature param, code in the header.
    YacHash(Round round, ProposalHash proposal, BlockHash block)
        : vote_round{round},
          vote_hashes{std::move(proposal), std::move(block)} {}

    YacHash() = default;

    /**
     * Round, in which peer voted
     */
    Round vote_round;

    /**
     * Contains hashes of proposal and block, for which peer voted
     */
    struct VoteHashes {
      /**
       * Hash computed from proposal
       */
      ProposalHash proposal_hash;

      /**
       * Hash computed from block;
       */
      BlockHash block_hash;

      std::string toString() const {
        return shared_model::detail::PrettyStringBuilder()
            .init("VoteHashes")
            .appendNamed("proposal", proposal_hash)
            .appendNamed("block", block_hash)
            .finalize();
      }
    };
    VoteHashes vote_hashes;

    /**
     * Peer signature of block
     */
    std::shared_ptr<shared_model::interface::Signature> block_signature;

    bool operator==(const YacHash &obj) const {
      return vote_round == obj.vote_round
          and vote_hashes.proposal_hash == obj.vote_hashes.proposal_hash
          and vote_hashes.block_hash == obj.vote_hashes.block_hash;
    };

    bool operator!=(const YacHash &obj) const {
      return not(*this == obj);
    };

    std::string toString() const {
      return shared_model::detail::PrettyStringBuilder()
          .init("YacHash")
          .appendNamed("round", vote_round)
          .appendNamed("hashes", vote_hashes)
          .finalize();
    }
  };

  /**
   * Provide methods related to hash operations in ya consensus
   */
  class YacHashProvider {
   public:
    /**
     * Make hash from block creator event
     */
    virtual YacHash makeHash(
        const simulator::BlockCreatorEvent &event) const = 0;

    /**
     * Convert YacHash to model hash
     * @param hash - for converting
     * @return HashType of model hash
     */
    virtual shared_model::interface::types::HashType toModelHash(
        const YacHash &hash) const = 0;

    virtual ~YacHashProvider() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_HASH_PROVIDER_HPP
