/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SIMULATOR_MOCKS_HPP
#define IROHA_SIMULATOR_MOCKS_HPP

#include <gmock/gmock.h>
#include "simulator/block_creator.hpp"

namespace iroha {
  namespace simulator {
    class MockBlockCreator : public BlockCreator {
     public:
      MOCK_METHOD2(
          processVerifiedProposal,
          std::optional<std::shared_ptr<shared_model::interface::Block>>(
              const std::shared_ptr<
                  iroha::validation::VerifiedProposalAndErrors> &,
              const TopBlockInfo &));
      MOCK_METHOD0(onBlock, rxcpp::observable<BlockCreatorEvent>());
    };
  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_SIMULATOR_MOCKS_HPP
