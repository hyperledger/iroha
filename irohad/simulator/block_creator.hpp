/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_CREATOR_HPP
#define IROHA_BLOCK_CREATOR_HPP

#include <rxcpp/rx.hpp>
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
       * Creates a block from given proposal and ledger state - top block height
       * and hash
       */
      virtual boost::optional<std::shared_ptr<shared_model::interface::Block>>
      processVerifiedProposal(
          const std::shared_ptr<validation::VerifiedProposalAndErrors>
              &verified_proposal_and_errors,
          shared_model::interface::types::HeightType height,
          const shared_model::crypto::Hash &top_hash) = 0;

      /**
       * Emit blocks made from proposals
       */
      virtual rxcpp::observable<BlockCreatorEvent> onBlock() = 0;

      virtual ~BlockCreator() = default;
    };
  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_BLOCK_CREATOR_HPP
