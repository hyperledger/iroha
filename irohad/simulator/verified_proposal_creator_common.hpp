/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VERIFIED_PROPOSAL_CREATOR_COMMON_HPP
#define IROHA_VERIFIED_PROPOSAL_CREATOR_COMMON_HPP

#include <boost/optional.hpp>
#include "ametsuchi/ledger_state.hpp"
#include "consensus/round.hpp"
#include "validation/stateful_validator_common.hpp"

namespace iroha {
  namespace simulator {

    /**
     * Event, which is emitted by verified proposal creator, when it receives
     * and processes a proposal
     */
    struct VerifiedProposalCreatorEvent {
      boost::optional<std::shared_ptr<validation::VerifiedProposalAndErrors>>
          verified_proposal_result;
      consensus::Round round;
      std::shared_ptr<const LedgerState> ledger_state;
    };

    std::shared_ptr<validation::VerifiedProposalAndErrors>
    getVerifiedProposalUnsafe(const VerifiedProposalCreatorEvent &event);

  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_VERIFIED_PROPOSAL_CREATOR_COMMON_HPP
