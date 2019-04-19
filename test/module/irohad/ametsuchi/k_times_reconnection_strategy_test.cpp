/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <memory>

#include "ametsuchi/reconnection/impl/k_times_reconnection_strategy.hpp"

using namespace iroha::ametsuchi;

class KTimesReconnectionStrategyTest : public testing::Test {
 public:
  void SetUp() override {
    strategy_ = std::make_shared<KTimesReconnectionStorageStrategy>(N_);
  }

  std::shared_ptr<iroha::ametsuchi::ReconnectionStorageStrategy> strategy_;
  const size_t N_{10};
  const KTimesReconnectionStorageStrategy::Tag tag = "tag";
};

/**
 * @given initialized reconnection strategy with N limit
 * @when  call canInvoke N times
 *        @and one more time
 * @then  check first N times returns true
 *        @and last time return false
 */
TEST_F(KTimesReconnectionStrategyTest, NormalCase) {
  for (size_t i = 0; i < N_; i++) {
    ASSERT_TRUE(strategy_->canInvoke(tag));
  }
  ASSERT_FALSE(strategy_->canInvoke(tag));
}

/**
 * @given initialized reconnection strategy with N limit
 * @when  call canInvoke one time,
 *        @and call reset
 *        @and call canInvoke N times
 * @then  all canInvoke return true
 */
TEST_F(KTimesReconnectionStrategyTest, ResetCheck) {
  strategy_->canInvoke(tag);
  strategy_->reset(tag);
  for (size_t i = 0; i < N_; i++) {
    ASSERT_TRUE(strategy_->canInvoke(tag));
  }
}

/**
 * @given initialized reconnection strategy
 * @when  call makeTag twice
 * @then  returned tags are different
 */
TEST_F(KTimesReconnectionStrategyTest, TagConsistency) {
  ASSERT_TRUE(strategy_->makeTag(tag) != strategy_->makeTag(tag));
}
