/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

using ::testing::ByMove;
using ::testing::Ref;
using ::testing::Return;
using ::testing::ReturnRefOfCopy;

struct MSTNotificationTest : public ::testing::Test {
  void SetUp() override {
  }
};

