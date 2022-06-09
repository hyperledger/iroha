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
    explicit YacHash(Round round)
        : vote_round{round} {}

    YacHash() = default;
    YacHash(YacHash&&) = default;

    YacHash& operator=(YacHash &&c) {
      if (this != &c) {
        vote_hashes = std::move(c.vote_hashes);
        vote_round = std::move(c.vote_round);
      }
      return *this;
    }

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

      /**
       * Peer signature of block
       */
      std::shared_ptr<shared_model::interface::Signature> block_signature;

      VoteHashes(ProposalHash const &proposal, BlockHash const &block)
          : proposal_hash(proposal), block_hash(block) {}

      std::string toString() const {
        return shared_model::detail::PrettyStringBuilder()
            .init("VoteHashes")
            .appendNamed("proposal", proposal_hash)
            .appendNamed("block", block_hash)
            .appendNamed("signatures", *block_signature)
            .finalize();
      }
    };
    std::vector<VoteHashes> vote_hashes;

    VoteHashes &appendHashes(ProposalHash const &proposal, BlockHash const &block) {
      return vote_hashes.emplace_back(proposal, block);
    }

    bool operator==(const YacHash &obj) const {
      bool equal = obj.vote_hashes.size() == vote_hashes.size()
          && vote_round == obj.vote_round;

      if (obj.vote_hashes.size() == vote_hashes.size())
        for (size_t ix = 0; ix < vote_hashes.size(); ++ix)
          equal = equal
              && obj.vote_hashes[ix].proposal_hash
                  == vote_hashes[ix].proposal_hash
              && obj.vote_hashes[ix].block_hash == vote_hashes[ix].block_hash;

      return equal;
    }

    bool operator!=(const YacHash &obj) const {
      return not(*this == obj);
    }

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
        const YacHash &hash, size_t index) const = 0;

    virtual ~YacHashProvider() = default;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_HASH_PROVIDER_HPP
