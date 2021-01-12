/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/unique_creation_proposal_strategy.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace iroha::ordering;

using testing::_;
using testing::Return;

class UniqueCreationProposalStrategyTest : public testing::Test {
 public:
  void SetUp() override {
    strategy_ = std::make_shared<UniqueCreationProposalStrategy>();
  }
  std::shared_ptr<UniqueCreationProposalStrategy> strategy_;
};

/**
 * @given initialized UniqueCreationProposalStrategy
 *        @and onCollaborationOutcome is invoked for the first round
 * @when  shouldCreateRound calls N times
 * @then  shouldCreateRound returns true
 */
TEST_F(UniqueCreationProposalStrategyTest, OnNonMaliciousCase) {
  ASSERT_TRUE(strategy_->shouldCreateRound({1, 0}));
  strategy_->onProposalRequest({1, 0});
  ASSERT_FALSE(strategy_->shouldCreateRound({1, 0}));

  ASSERT_TRUE(strategy_->shouldCreateRound({2, 0}));
  strategy_->onProposalRequest({2, 0});
  ASSERT_FALSE(strategy_->shouldCreateRound({2, 0}));
}
