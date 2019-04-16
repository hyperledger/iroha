/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <datetime/time.hpp>

TEST(Time, Now) {
  auto time = iroha::time::now();
  std::cout << "Unix timestamp64: " << time << std::endl;

  ASSERT_GT(time, 1497447645000);  // 06/14/2017 @ 1:40pm (UTC)
  ASSERT_EQ(sizeof(time), 8);
}
