/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/buffered_cleanup_strategy.hpp"

#include <memory>

#include <gtest/gtest.h>

using namespace iroha::consensus::yac;

using Round = iroha::consensus::Round;

class BufferedCleanupStrategyTest : public ::testing::Test {
 public:
  std::shared_ptr<CleanupStrategy> strategy_;

  void SetUp() override {
    strategy_ = std::make_shared<BufferedCleanupStrategy>();
  }

  RejectMessage makeMockReject() {
    return RejectMessage({});
  }

  CommitMessage makeMockCommit() {
    return CommitMessage({});
  }
};

/**
 * Reject first case
 * @given empty strategy
 * @when  insert reject message for (1, 1)
 *        @and insert commit message for (1, 2)
 * @then  checks that reject is inserted and there is nothing to delete
 *        @and checks commit is inserted and reject is removed
 */
TEST_F(BufferedCleanupStrategyTest, RejectFirstCase) {
  ASSERT_TRUE(strategy_->shouldCreateRound({1, 1}));
  ASSERT_EQ(boost::none, strategy_->finalize({1, 1}, makeMockReject()));

  ASSERT_TRUE(strategy_->shouldCreateRound({1, 2}));

  auto removed_rounds = strategy_->finalize({1, 2}, makeMockCommit());
  ASSERT_TRUE(removed_rounds);
  ASSERT_EQ(1, removed_rounds->size());
  ASSERT_EQ((Round{1, 1}), removed_rounds->at(0));
}

/**
 * On new commit case
 * @given strategy with committed (1,1) are rejected (2,1) states
 * @when  commit for (2, 2) is finalized
 * @then  previous rounds (1, 1) and (2, 1) are removed
 */
TEST_F(BufferedCleanupStrategyTest, OnNewCommitCase) {
  strategy_->shouldCreateRound({1, 1});
  ASSERT_FALSE(strategy_->finalize({1, 1}, makeMockCommit()));

  strategy_->shouldCreateRound({2, 1});
  ASSERT_FALSE(strategy_->finalize({1, 2}, makeMockReject()));

  strategy_->shouldCreateRound({2, 2});
  auto removed = strategy_->finalize({2, 2}, makeMockCommit());
  ASSERT_TRUE(removed);
  ASSERT_EQ(2, removed->size());
  ASSERT_EQ((Round{1, 1}), removed->at(0));
  ASSERT_EQ((Round{2, 1}), removed->at(1));
}

/**
 * Many not finalized rounds
 * @given initialized strategy
 *        @and create many uncommitted rounds from (1, 1) to (1, 9)
 * @when  invoke finalization for (1, 7)
 * @then  check that all rounds before (1, 7) are removed
 */
TEST_F(BufferedCleanupStrategyTest, FinalizeWhenManyRounds) {
  for (auto i = 1u; i < 10; ++i) {
    ASSERT_TRUE(strategy_->shouldCreateRound(Round{1, i}));
  }
  auto removed = strategy_->finalize({1, 7}, makeMockCommit());
  ASSERT_TRUE(removed);
  ASSERT_EQ(6, removed->size());
  for (auto i = 0u; i < 6; ++i) {
    ASSERT_EQ((Round{1, i + 1}), removed->at(i));
  }
}
