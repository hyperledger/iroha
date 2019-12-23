/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/to_string.hpp"

#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <boost/optional.hpp>
#include <boost/range/any_range.hpp>

const std::string kTestString("test");

struct MockToStringable {
  MOCK_CONST_METHOD0(toString, std::string());
};

std::unique_ptr<MockToStringable> makeObj(std::string string = kTestString) {
  auto obj = std::make_unique<MockToStringable>();
  EXPECT_CALL(*obj, toString()).WillOnce(::testing::Return(string));
  return obj;
}

using namespace iroha::to_string;

/**
 * @given std::string
 * @when toString is called on it
 * @then result equals argument
 */
TEST(ToStringTest, StdString) {
  const std::string string("Wake up, Neo...");
  ASSERT_EQ(toString(string), string);
}

/**
 * @given several plain types that std::to_string accepts
 * @when toString is called on them
 * @then they are converted as std::to_string does
 */
TEST(ToStringTest, PlainValues) {
  auto test = [](auto o) { EXPECT_EQ(toString(o), std::to_string(o)); };
  test(404);
  test(-273);
  test(15.7f);
  test(true);
}

/**
 * @given ToStringable object
 * @when toString is called on it
 * @then result equals expected string
 */
TEST(ToStringTest, ToStringMethod) {
  EXPECT_EQ(toString(*makeObj()), kTestString);
}

/**
 * @given ToStringable object wrapped in pointers and optionals
 * @when toString is called on it
 * @then result equals expected string
 */
TEST(ToStringTest, WrappedDereferenceable) {
  // start with unique_ptr
  std::unique_ptr<MockToStringable> o1 = makeObj();
  MockToStringable *raw_obj = o1.get();
  EXPECT_EQ(toString(o1), kTestString);
  // wrap it into optional
  auto o2 = boost::make_optional(std::move(o1));
  EXPECT_CALL(*raw_obj, toString()).WillOnce(::testing::Return(kTestString));
  EXPECT_EQ(toString(o2), kTestString);
  // wrap it into shared_ptr
  auto o3 = std::make_shared<decltype(o2)>(std::move(o2));
  EXPECT_CALL(*raw_obj, toString()).WillOnce(::testing::Return(kTestString));
  EXPECT_EQ(toString(o3), kTestString);
  // wrap it into one more optional
  auto o4 = boost::make_optional(std::move(o3));
  EXPECT_CALL(*raw_obj, toString()).WillOnce(::testing::Return(kTestString));
  EXPECT_EQ(toString(o4), kTestString);
}

/**
 * @given unset pointers and optional
 * @when toString is called on them
 * @then result has "not set"
 */
TEST(ToStringTest, UnsetDereferenceable) {
  auto test = [](const auto &o) { EXPECT_EQ(toString(o), "(not set)"); };
  test(std::unique_ptr<int>{});
  test(std::shared_ptr<int>{});
  test(static_cast<int *>(0));
  test(boost::optional<int>());
  test(boost::none);
}

/**
 * @given vector of unique_ptr<ToStringable> objects
 * @when toString is called on it
 * @then result equals expected string
 */
TEST(ToStringTest, VectorOfUniquePointers) {
  std::vector<std::unique_ptr<MockToStringable>> vec;
  EXPECT_EQ(toString(vec), "[]");
  vec.push_back(makeObj("el1"));
  vec.push_back(makeObj("el2"));
  vec.push_back(nullptr);
  EXPECT_EQ(toString(vec), "[el1, el2, (not set)]");
}

/**
 * @given vector of unique_ptr<ToStringable> objects
 * @when toString is called on it
 * @then result equals expected string
 */
TEST(ToStringTest, BoostAnyRangeOfSharedPointers) {
  std::vector<std::shared_ptr<MockToStringable>> vec;
  vec.push_back(makeObj("el1"));
  vec.push_back(makeObj("el2"));
  vec.push_back(nullptr);
  boost::any_range<std::shared_ptr<MockToStringable>,
                   boost::forward_traversal_tag,
                   const std::shared_ptr<MockToStringable> &>
      range;
  EXPECT_EQ(toString(range), "[]");
  range = vec;
  EXPECT_EQ(toString(range), "[el1, el2, (not set)]");
}
