/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/k_times_reconnection_strategy.hpp"

#include <gtest/gtest.h>

using namespace iroha::ametsuchi;

/**
 * @given initialized strategy with k limit
 * @when  canReconnect is invoked k + 1 times
 * @then  it returns true k times
 *        @and returns false last time
 */
TEST(KTimesReconnectionStrategyTest, FirstUse) {
  size_t K = 10;
  KTimesReconnectionStrategy strategy(K);

  for (size_t i = 0; i < K; ++i) {
    ASSERT_TRUE(strategy.canReconnect());
  }
  ASSERT_FALSE(strategy.canReconnect());
}

/**
 * @given initialized strategy with k limit
 *        @and canReconnect is invoked k times
 * @when  reset method is invoked
 *        @and canReconnect is invoked k + 1 times
 * @then  checks that strategy returns true k times
 *        @and it returns false last time
 */
TEST(KTimesReconnectionStrategyTest, UseAfterReset) {
  size_t K = 10;
  KTimesReconnectionStrategy strategy(K);
  for (size_t i = 0; i < K; ++i) {
    strategy.canReconnect();
  }
  strategy.reset();
  for (size_t i = 0; i < K; ++i) {
    ASSERT_TRUE(strategy.canReconnect());
  }
  ASSERT_FALSE(strategy.canReconnect());
}
