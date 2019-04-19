/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROPOSAL_CREATION_STRATEGY_STUB_HPP
#define IROHA_PROPOSAL_CREATION_STRATEGY_STUB_HPP

#include "ordering/ordering_service_proposal_creation_strategy.hpp"

namespace iroha {
  namespace ordering {

    /**
     * Stub implementation for testing purposes.
     */
    struct ProposalCreationStrategyStub final
        : public ProposalCreationStrategy {
     public:
      void onCollaborationOutcome(const PeerList &peers) override {}

      void shouldCreateRound(RoundType round,
                             const std::function<void()> &) override {}

      boost::optional<RoundType> onProposalRequest(
          const PeerType &who, RoundType requested_round) override {
        return boost::none;
      }
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_PROPOSAL_CREATION_STRATEGY_STUB_HPP
