/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "utils/reference_holder.hpp"

#include <gtest/gtest.h>

/**
 * @given lvalue
 * AND corresponding reference holder
 * @when value is modified
 * @then reference holder dereference returns new value
 */
TEST(ReferenceHolder, lvalue) {
  int i{2};
  shared_model::detail::ReferenceHolder<int> rh(i);
  ASSERT_EQ(*rh, i);
  i = 3;
  ASSERT_EQ(*rh, i);
}

/**
 * @given rvalue
 * AND corresponding reference holder
 * @when value is modified
 * @then reference holder dereference returns new value
 */
TEST(ReferenceHolder, rvalue) {
  shared_model::detail::ReferenceHolder<int> rh(2);
  ASSERT_EQ(*rh, 2);
  *rh = 3;
  ASSERT_EQ(*rh, 3);
}

/**
 * @given rvalue
 * AND corresponding const reference holder
 * @when value is accessed
 * @then reference holder dereference returns stored value
 */
TEST(ReferenceHolder, ConstAccess) {
  const shared_model::detail::ReferenceHolder<int> rh(2);
  ASSERT_EQ(*rh, 2);
}
