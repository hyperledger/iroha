/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_PROPOSAL_CREATION_STRATEGY_HPP
#define IROHA_MOCK_PROPOSAL_CREATION_STRATEGY_HPP

#include "ordering/ordering_service_proposal_creation_strategy.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ordering {
    class MockProposalCreationStrategy : public ProposalCreationStrategy {
     public:
      MOCK_METHOD2(onCollaborationOutcome, void(RoundType, size_t));
      MOCK_METHOD1(shouldCreateRound, bool(RoundType));
      MOCK_METHOD1(onProposalRequest, boost::optional<RoundType>(RoundType));
    };
  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_MOCK_PROPOSAL_CREATION_STRATEGY_HPP
