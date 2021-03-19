/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_CREATOR_HPP
#define IROHA_BLOCK_CREATOR_HPP

#include <rxcpp/rx-observable-fwd.hpp>
#include "simulator/block_creator_common.hpp"

namespace iroha {
  namespace validation {
    struct VerifiedProposalAndErrors;
  }

  namespace simulator {

    /**
     * Interface for creating blocks from proposal
     */
    class BlockCreator {
     public:
      /**
       * Creates a block from given proposal and top block info
       */
      virtual boost::optional<std::shared_ptr<shared_model::interface::Block>>
      processVerifiedProposal(
          const std::shared_ptr<validation::VerifiedProposalAndErrors>
              &verified_proposal_and_errors,
          const TopBlockInfo &top_block_info) = 0;

      virtual ~BlockCreator() = default;
    };
  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_BLOCK_CREATOR_HPP
