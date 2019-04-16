/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/util.hpp"
#include "commands.pb.h"

#include <gtest/gtest.h>

using namespace iroha;
using namespace shared_model::proto;
using shared_model::crypto::toBinaryString;

/**
 * @given some protobuf object
 * @when making a blob from it
 * @then make sure that the deserialized from string is the same
 */
TEST(UtilTest, StringFromMakeBlob) {
  protocol::SetAccountQuorum base, deserialized;
  base.set_quorum(100);
  auto blob = makeBlob(base);

  ASSERT_TRUE(deserialized.ParseFromString(toBinaryString(blob)));
  ASSERT_EQ(deserialized.quorum(), base.quorum());
}
