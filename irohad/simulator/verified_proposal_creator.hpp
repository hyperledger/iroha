/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VERIFIED_PROPOSAL_CREATOR_HPP
#define IROHA_VERIFIED_PROPOSAL_CREATOR_HPP

#include <rxcpp/rx-observable-fwd.hpp>
#include "simulator/verified_proposal_creator_common.hpp"

namespace shared_model {
  namespace interface {
    class Proposal;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace consensus {
    struct Round;
  }  // namespace consensus

  namespace simulator {

    /**
     * Interface for providing proposal validation
     */
    class VerifiedProposalCreator {
     public:
      /**
       * Execute stateful validation for given proposal
       */
      virtual std::shared_ptr<validation::VerifiedProposalAndErrors>
      processProposal(const shared_model::interface::Proposal &proposal) = 0;

      /**
       * Emit proposals which were verified by stateful validator
       */
      virtual rxcpp::observable<VerifiedProposalCreatorEvent>
      onVerifiedProposal() = 0;

      virtual ~VerifiedProposalCreator() = default;
    };
  }  // namespace simulator
}  // namespace iroha
#endif  // IROHA_VERIFIED_PROPOSAL_CREATOR_HPP
