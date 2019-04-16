/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/json_block_factory.hpp"

#include <gtest/gtest.h>

#include "framework/test_logger.hpp"

using namespace iroha;
using namespace iroha::model;
using namespace iroha::model::converters;

class JsonBlockTest : public ::testing::Test {
 public:
  JsonBlockFactory factory{getTestLogger("JsonBlockFactory")};
};

TEST_F(JsonBlockTest, ValidWhenWellFormed) {
  Block orig_block{};

  auto json_block = factory.serialize(orig_block);
  auto serial_block = factory.deserialize(json_block);

  ASSERT_EQ(orig_block, serial_block);
}

TEST_F(JsonBlockTest, InvalidWhenFieldsMissing) {
  Block orig_block{};

  auto json_block = factory.serialize(orig_block);

  json_block.RemoveMember("created_ts");

  auto serial_block = factory.deserialize(json_block);

  ASSERT_FALSE(serial_block);
}
