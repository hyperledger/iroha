/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "model/commands/add_asset_quantity.hpp"
#include "model/converters/json_common.hpp"
#include "model/converters/json_transaction_factory.hpp"

using namespace iroha;
using namespace iroha::model;
using namespace iroha::model::converters;

class JsonTransactionTest : public ::testing::Test {
 public:
  JsonTransactionFactory factory;
};

TEST_F(JsonTransactionTest, ValidWhenWellFormed) {
  Transaction transaction{};
  transaction.signatures.emplace_back();
  transaction.commands.push_back(std::make_shared<AddAssetQuantity>());

  auto json_transaction = factory.serialize(transaction);
  auto serial_transaction = factory.deserialize(json_transaction);

  ASSERT_TRUE(serial_transaction);
  ASSERT_EQ(transaction, *serial_transaction);
}

TEST_F(JsonTransactionTest, InvalidWhenFieldsMissing) {
  Transaction transaction{};

  auto json_transaction = factory.serialize(transaction);

  json_transaction.RemoveMember("created_ts");

  auto serial_transaction = factory.deserialize(json_transaction);

  ASSERT_FALSE(serial_transaction);
}

TEST_F(JsonTransactionTest, InvalidWhenNegativeAddAssetQuantity) {
  auto transaction_string = R"({
    "signatures": [
        {
            "pubkey": "f24325aa9b91526a83e722e19fa2a3ad7f3966abe066a9302b5d2092fe960254",
            "signature": "4563f8de6ee45e44b462a7027d1640376dece03eaf1091f8e69cdc9531957b178f00667e9241ba2d09f49b7861419b89af4986eb4d332e9d7efb31bb1105890e"
        }
    ],
    "created_ts": 1503845603221,
    "creator_account_id": "admin@test",
    "quorum": 5,
    "commands": [
        {
            "command_type": "CreateAsset",
            "asset_name": "usd",
            "domain_id": "test",
            "precision": "2"
        },
        {
            "command_type": "AddAssetQuantity",
            "account_id": "admin@test",
            "asset_id": "usd#test",
            "amount": {
                "int_part": -20,
                "frac_part": 0
            }
        }
    ]
  })";
  auto json = stringToJson(transaction_string);

  ASSERT_TRUE(json);

  auto transaction = factory.deserialize(json.value());

  ASSERT_FALSE(transaction);
}
