/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SIMULATOR_MOCKS_HPP
#define IROHA_SIMULATOR_MOCKS_HPP

#include <gmock/gmock.h>
#include "simulator/block_creator.hpp"
#include "simulator/verified_proposal_creator_common.hpp"

namespace iroha {
  namespace simulator {
    class MockBlockCreator : public BlockCreator {
     public:
      MOCK_METHOD(BlockCreatorEvent,
                  processVerifiedProposal,
                  (VerifiedProposalCreatorEvent const &),
                  (override));
    };
  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_SIMULATOR_MOCKS_HPP
