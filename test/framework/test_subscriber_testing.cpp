/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "framework/test_subscriber.hpp"

#include <iostream>

using namespace framework::test_subscriber;

class TestSubscriberTesting : public ::testing::Test {};

TEST_F(TestSubscriberTesting, ValidCallExactTest) {
  auto ints = rxcpp::observable<>::create<int>([](auto s) {
    s.on_next(1);
    s.on_next(2);
    s.on_completed();
  });

  auto number_of_calls = 0;

  auto wrapper = make_test_subscriber<CallExact>(ints, 2);
  wrapper.subscribe([&number_of_calls](auto val) { ++number_of_calls; });

  ASSERT_TRUE(wrapper.validate());
  ASSERT_EQ(2, number_of_calls);
}

TEST_F(TestSubscriberTesting, UnsatisfiedCallExactTest) {
  auto ints = rxcpp::observable<>::create<int>([](auto s) {
    s.on_next(1);
    s.on_next(2);
    s.on_completed();
  });

  auto number_of_calls = 0;

  auto wrapper = make_test_subscriber<CallExact>(ints, 555);
  wrapper.subscribe([&number_of_calls](auto val) { ++number_of_calls; });
  ASSERT_FALSE(wrapper.validate());
  ASSERT_EQ(2, number_of_calls);
}

TEST_F(TestSubscriberTesting, DefaultSubscriberTest) {
  auto one = rxcpp::observable<>::just(0);

  auto wrapper = make_test_subscriber<CallExact>(one, 1);
  wrapper.subscribe();

  ASSERT_TRUE(wrapper.validate());
}
