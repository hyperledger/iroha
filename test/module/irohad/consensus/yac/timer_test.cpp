/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/timer_impl.hpp"

#include <gtest/gtest.h>

using namespace iroha::consensus::yac;

class TimerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    timer = std::make_shared<TimerImpl>(delay);
  }

  void TearDown() override {
    timer.reset();
  }

 public:
  std::chrono::milliseconds delay{0};
  std::shared_ptr<Timer> timer;
};

TEST_F(TimerTest, FirstInvokedWhenOneSubmitted) {
  int status = 0;

  timer->invokeAfterDelay([&status] { status = 1; });
  ASSERT_EQ(status, 1);
}

TEST_F(TimerTest, SecondInvokedWhenTwoSubmitted) {
  int status = 0;

  timer->invokeAfterDelay([&status] { status = 1; });
  timer->invokeAfterDelay([&status] { status = 2; });
  ASSERT_EQ(status, 2);
}
