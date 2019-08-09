/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/kick_out_proposal_creation_strategy.hpp"

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "module/irohad/consensus/yac/mock_yac_supermajority_checker.hpp"

using namespace iroha::ordering;

using testing::_;
using testing::Return;

class KickOutProposalCreationStrategyTest : public testing::Test {
 public:
  void SetUp() override {
    supermajority_checker_ =
        std::make_shared<iroha::consensus::yac::MockSupermajorityChecker>();
    strategy_ = std::make_shared<KickOutProposalCreationStrategy>(
        supermajority_checker_);
  }

  std::shared_ptr<KickOutProposalCreationStrategy> strategy_;
  std::shared_ptr<iroha::consensus::yac::MockSupermajorityChecker>
      supermajority_checker_;

  size_t number_of_peers = 7;
  size_t f = 2;
};

/**
 * @given initialized kickOutStrategy
 *        @and onCollaborationOutcome is invoked for the first round
 * @when  onProposal calls F times for further rounds
 * @then  shouldCreateRound returns true
 */
TEST_F(KickOutProposalCreationStrategyTest, OnNonMaliciousCase) {
  EXPECT_CALL(*supermajority_checker_, isTolerated(0, number_of_peers))
      .WillOnce(Return(false));

  strategy_->onCollaborationOutcome({1, 0}, number_of_peers);

  ASSERT_TRUE(strategy_->shouldCreateRound({2, 0}));

  for (auto i = 0u; i < f; ++i) {
    strategy_->onProposalRequest({2, 0});
  }

  EXPECT_CALL(*supermajority_checker_, isTolerated(f, number_of_peers))
      .WillOnce(Return(false));
  ASSERT_TRUE(strategy_->shouldCreateRound({2, 0}));
}

/**
 * @given initialized kickOutStrategy
 *        @and onCollaborationOutcome is invoked for the first round
 * @when  onProposal calls F + 1 times for further rounds
 * @then  shouldCreateRound returns false
 */
TEST_F(KickOutProposalCreationStrategyTest, OnMaliciousCase) {
  strategy_->onCollaborationOutcome({1, 0}, number_of_peers);

  auto requested = f + 1;
  for (auto i = 0u; i < requested; ++i) {
    strategy_->onProposalRequest({2, 0});
  }

  EXPECT_CALL(*supermajority_checker_, isTolerated(requested, number_of_peers))
      .WillOnce(Return(true));
  ASSERT_FALSE(strategy_->shouldCreateRound({2, 0}));
}
