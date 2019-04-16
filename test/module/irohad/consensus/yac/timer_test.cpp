/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/timer_impl.hpp"

#include <gtest/gtest.h>
#include <rxcpp/rx-test.hpp>

using namespace iroha::consensus::yac;

class TimerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    timer = std::make_shared<TimerImpl>(delay, coordination);
  }

  void TearDown() override {
    timer.reset();
  }

  void invokeTimer() {
    worker.start();
  }

 public:
  std::chrono::milliseconds delay{0};
  rxcpp::schedulers::test::test_worker worker =
      rxcpp::schedulers::make_test().create_worker();
  rxcpp::observe_on_one_worker coordination{
      rxcpp::schedulers::make_same_worker(worker)};
  std::shared_ptr<Timer> timer;
};

TEST_F(TimerTest, NothingInvokedWhenDenied) {
  int status = 0;

  timer->invokeAfterDelay([&status] { status = 1; });
  timer->deny();
  invokeTimer();
  ASSERT_EQ(status, 0);
}

TEST_F(TimerTest, FirstInvokedWhenOneSubmitted) {
  int status = 0;

  timer->invokeAfterDelay([&status] { status = 1; });
  invokeTimer();
  ASSERT_EQ(status, 1);
}

TEST_F(TimerTest, SecondInvokedWhenTwoSubmitted) {
  int status = 0;

  timer->invokeAfterDelay([&status] { status = 1; });
  timer->invokeAfterDelay([&status] { status = 2; });
  invokeTimer();
  ASSERT_EQ(status, 2);
}
