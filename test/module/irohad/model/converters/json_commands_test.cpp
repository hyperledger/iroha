/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>

#include <gtest/gtest.h>

#include "model/commands/add_asset_quantity.hpp"
#include "model/commands/add_peer.hpp"
#include "model/commands/add_signatory.hpp"
#include "model/commands/append_role.hpp"
#include "model/commands/create_account.hpp"
#include "model/commands/create_asset.hpp"
#include "model/commands/create_domain.hpp"
#include "model/commands/create_role.hpp"
#include "model/commands/detach_role.hpp"
#include "model/commands/grant_permission.hpp"
#include "model/commands/remove_signatory.hpp"
#include "model/commands/revoke_permission.hpp"
#include "model/commands/set_account_detail.hpp"
#include "model/commands/set_quorum.hpp"
#include "model/commands/subtract_asset_quantity.hpp"
#include "model/commands/transfer_asset.hpp"
#include "model/converters/json_command_factory.hpp"
#include "model/permissions.hpp"
#include "model/sha3_hash.hpp"

using namespace rapidjson;
using namespace iroha;
using namespace iroha::model;
using namespace iroha::model::converters;
using namespace shared_model::permissions;

class JsonCommandTest : public ::testing::Test {
 public:
  JsonCommandFactory factory;

  void command_converter_test(std::shared_ptr<Command> abstract_command) {
    auto json_repr = factory.serializeAbstractCommand(abstract_command);
    auto model_repr = factory.deserializeAbstractCommand(json_repr);
    ASSERT_TRUE(model_repr);
    ASSERT_EQ(*abstract_command, *(*model_repr));
  }
};

TEST_F(JsonCommandTest, ClassHandlerTest) {
  std::vector<std::shared_ptr<Command>> commands = {
      std::make_shared<AddAssetQuantity>(),
      std::make_shared<SubtractAssetQuantity>(),
      std::make_shared<AddPeer>(),
      std::make_shared<AddSignatory>(),
      std::make_shared<CreateAccount>(),
      std::make_shared<CreateAsset>("", "", 0),
      std::make_shared<CreateDomain>(),
      std::make_shared<RemoveSignatory>(),
      std::make_shared<SetQuorum>("", 0),
      std::make_shared<TransferAsset>(),
      std::make_shared<DetachRole>()};
  for (const auto &command : commands) {
    auto ser = factory.serializeAbstractCommand(command);
    auto des = factory.deserializeAbstractCommand(ser);
    ASSERT_TRUE(des);
    ASSERT_EQ(**des, *command);
  }
}

TEST_F(JsonCommandTest, InvalidWhenUnknownCommandType) {
  auto cmd = R"({
    "command_type": "Unknown",
    "account_id": "admin@test",
    "asset_id": "usd#test",
    "description": "testdescription",
    "amount": {
        "int_part": -20,
        "frac_part": 0
    }
  })";

  auto json = stringToJson(cmd);
  ASSERT_TRUE(json);
  ASSERT_FALSE(factory.deserializeAbstractCommand(*json));
}

TEST_F(JsonCommandTest, create_domain) {
  auto orig_command = std::make_shared<CreateDomain>("soramitsu", "jp-user");
  auto json = factory.serializeCreateDomain(orig_command);
  auto serial_command = factory.deserializeCreateDomain(json);
  ASSERT_EQ(*orig_command, **serial_command);
  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, add_asset_quantity) {
  auto orig_command = std::make_shared<AddAssetQuantity>();

  orig_command->amount = "1.50";
  orig_command->asset_id = "23";
  orig_command->description = "testdescription";

  auto json_command = factory.serializeAddAssetQuantity(orig_command);
  auto serial_command = factory.deserializeAddAssetQuantity(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);
  command_converter_test(orig_command);
}

/**
 * @given SubtractAssetQuantity
 * @when Set all data
 * @then Return Json Data
 */
TEST_F(JsonCommandTest, subtract_asset_quantity) {
  auto orig_command = std::make_shared<SubtractAssetQuantity>();

  orig_command->amount = "1.50";
  orig_command->asset_id = "23";

  auto json_command = factory.serializeSubtractAssetQuantity(orig_command);
  auto serial_command = factory.deserializeSubtractAssetQuantity(json_command);

  ASSERT_TRUE(*serial_command);
  ASSERT_EQ(*orig_command, **serial_command);
  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, add_peer) {
  auto orig_addPeer = std::make_shared<AddPeer>();
  orig_addPeer->peer.address = "10.90.129.23";
  auto proto_add_peer = factory.serializeAddPeer(orig_addPeer);
  auto deserialized_addPeer = factory.deserializeAddPeer(proto_add_peer);

  ASSERT_TRUE(deserialized_addPeer);
  ASSERT_EQ(*orig_addPeer, **deserialized_addPeer);
  command_converter_test(orig_addPeer);

  orig_addPeer->peer.address = "134";
  ASSERT_NE(**deserialized_addPeer, *orig_addPeer);
}

TEST_F(JsonCommandTest, add_signatory) {
  auto orig_command = std::make_shared<AddSignatory>();
  orig_command->account_id = "23";

  auto json_command = factory.serializeAddSignatory(orig_command);
  auto serial_command = factory.deserializeAddSignatory(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);
  command_converter_test(orig_command);

  orig_command->account_id = "100500";
  ASSERT_NE(*orig_command, **serial_command);
}

TEST_F(JsonCommandTest, add_signatory_abstract_factory) {
  auto orig_command = std::make_shared<AddSignatory>();
  orig_command->account_id = "23";

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, create_asset) {
  auto orig_command = std::make_shared<CreateAsset>();
  orig_command->domain_id = "kek_cheburek";
  orig_command->precision = 1;
  orig_command->asset_name = "test_asset";

  auto json_command = factory.serializeCreateAsset(orig_command);
  auto serial_command = factory.deserializeCreateAsset(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, create_account) {
  auto orig_command = std::make_shared<CreateAccount>();
  orig_command->account_name = "keker";
  orig_command->domain_id = "cheburek";

  auto json_command = factory.serializeCreateAccount(orig_command);
  auto serial_command = factory.deserializeCreateAccount(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);
  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, set_account_detail) {
  auto orig_command = std::make_shared<SetAccountDetail>();
  orig_command->account_id = "kek";
  orig_command->key = "key";
  orig_command->value = "value";

  auto json_command = factory.serializeSetAccountDetail(orig_command);
  auto serial_command = factory.deserializeSetAccountDetail(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);
  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, remove_signatory) {
  auto orig_command = std::make_shared<RemoveSignatory>();
  orig_command->account_id = "Vasya";
  std::fill(orig_command->pubkey.begin(), orig_command->pubkey.end(), 0xF);

  auto json_command = factory.serializeRemoveSignatory(orig_command);
  auto serial_command = factory.deserializeRemoveSignatory(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, set_account_quorum) {
  auto orig_command = std::make_shared<SetQuorum>();
  orig_command->new_quorum = 11;
  orig_command->account_id = "Vasya";

  auto json_command = factory.serializeSetQuorum(orig_command);
  auto serial_command = factory.deserializeSetQuorum(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, set_transfer_asset) {
  auto orig_command = std::make_shared<TransferAsset>();
  orig_command->amount = {1, 20};
  orig_command->asset_id = "tugrik";
  orig_command->src_account_id = "Vasya";
  orig_command->dest_account_id = "Petya";
  orig_command->description = "from Vasya to Petya with love";

  auto json_command = factory.serializeTransferAsset(orig_command);
  auto serial_command = factory.deserializeTransferAsset(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, append_role) {
  auto orig_command = std::make_shared<AppendRole>("test@test", "master");
  auto json_command = factory.serializeAppendRole(orig_command);
  auto serial_command = factory.deserializeAppendRole(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, detach_role) {
  auto orig_command = std::make_shared<DetachRole>("test@test", "master");
  auto json_command = factory.serializeDetachRole(orig_command);
  auto serial_command = factory.deserializeDetachRole(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, create_role) {
  std::set<std::string> perms = {
      can_get_my_account, can_create_asset, can_add_peer};
  auto orig_command = std::make_shared<CreateRole>("master", perms);
  auto json_command = factory.serializeCreateRole(orig_command);
  auto serial_command = factory.deserializeCreateRole(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  model::Transaction tx1, tx2;
  tx1.commands.push_back(orig_command);
  tx2.commands.push_back(*serial_command);
  ASSERT_EQ(iroha::hash(tx1), iroha::hash(tx2));

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, grant_permission) {
  auto orig_command =
      std::make_shared<GrantPermission>("admin@test", "can_read");
  auto json_command = factory.serializeGrantPermission(orig_command);
  auto serial_command = factory.deserializeGrantPermission(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}

TEST_F(JsonCommandTest, revoke_permission) {
  auto orig_command =
      std::make_shared<RevokePermission>("admin@test", "can_read");
  auto json_command = factory.serializeRevokePermission(orig_command);
  auto serial_command = factory.deserializeRevokePermission(json_command);

  ASSERT_TRUE(serial_command);
  ASSERT_EQ(*orig_command, **serial_command);

  command_converter_test(orig_command);
}
