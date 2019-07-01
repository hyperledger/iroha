/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "commands.pb.h"
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
#include "model/commands/set_quorum.hpp"
#include "model/commands/subtract_asset_quantity.hpp"
#include "model/commands/transfer_asset.hpp"

#include "model/converters/pb_command_factory.hpp"
#include "model/permissions.hpp"

using namespace iroha::model;
using namespace shared_model::permissions;

void command_converter_test(iroha::model::Command &abstract_command) {
  auto factory = iroha::model::converters::PbCommandFactory();
  auto pb_repr = factory.serializeAbstractCommand(abstract_command);
  auto model_repr = factory.deserializeAbstractCommand(pb_repr);
  ASSERT_EQ(abstract_command, *model_repr);
}

TEST(CommandTest, add_asset_quantity) {
  auto orig_command = iroha::model::AddAssetQuantity();

  orig_command.amount = "5.0";
  orig_command.asset_id = "23";

  auto factory = iroha::model::converters::PbCommandFactory();
  auto proto_command = factory.serializeAddAssetQuantity(orig_command);
  auto serial_command = factory.deserializeAddAssetQuantity(proto_command);

  ASSERT_EQ(orig_command, serial_command);
  command_converter_test(orig_command);
}

/**
 * @given SubtractAssetQuantity
 * @when Set all data
 * @then Return Protobuf Data
 */
TEST(CommandTest, subtract_asset_quantity) {
  auto orig_command = iroha::model::SubtractAssetQuantity();

  orig_command.amount = "5.0";
  orig_command.asset_id = "23";

  auto factory = iroha::model::converters::PbCommandFactory();
  auto proto_command = factory.serializeSubtractAssetQuantity(orig_command);
  auto serial_command = factory.deserializeSubtractAssetQuantity(proto_command);

  ASSERT_EQ(orig_command, serial_command);
  command_converter_test(orig_command);
}

TEST(CommandTest, add_peer) {
  auto orig_addPeer = iroha::model::AddPeer();
  orig_addPeer.peer.address = "10.90.129.23";

  auto factory = iroha::model::converters::PbCommandFactory();

  auto proto_add_peer = factory.serializeAddPeer(orig_addPeer);
  const auto &deserialized_addPeer = factory.deserializeAddPeer(proto_add_peer);

  ASSERT_EQ(orig_addPeer, deserialized_addPeer);
  command_converter_test(orig_addPeer);

  orig_addPeer.peer.address = "134";
  ASSERT_NE(deserialized_addPeer, orig_addPeer);
}

TEST(CommandTest, add_signatory) {
  auto orig_command = iroha::model::AddSignatory();
  orig_command.account_id = "23";

  auto factory = iroha::model::converters::PbCommandFactory();
  auto proto_command = factory.serializeAddSignatory(orig_command);
  auto serial_command = factory.deserializeAddSignatory(proto_command);

  ASSERT_EQ(orig_command, serial_command);
  command_converter_test(orig_command);

  orig_command.account_id = "100500";
  ASSERT_NE(orig_command, serial_command);
}

TEST(CommandTest, add_signatory_abstract_factory) {
  auto orig_command = iroha::model::AddSignatory();
  orig_command.account_id = "23";

  command_converter_test(orig_command);
}

TEST(CommandTest, create_domain) {
  auto factory = iroha::model::converters::PbCommandFactory();
  auto orig_command = CreateDomain("soramitsu", "jp-user");
  auto proto_command = factory.serializeCreateDomain(orig_command);
  auto serial_command = factory.deserializeCreateDomain(proto_command);
  ASSERT_EQ(orig_command, serial_command);
  command_converter_test(orig_command);
}

TEST(CommandTest, create_asset) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = iroha::model::CreateAsset();
  orig_command.domain_id = "kek_cheburek";
  orig_command.precision = 1;
  orig_command.asset_name = "test_asset";

  auto proto_command = factory.serializeCreateAsset(orig_command);
  auto serial_command = factory.deserializeCreateAsset(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

TEST(CommandTest, create_account) {
  auto orig_command = iroha::model::CreateAccount();
  orig_command.account_name = "keker";
  orig_command.domain_id = "cheburek";
  auto factory = iroha::model::converters::PbCommandFactory();
  auto proto_command = factory.serializeCreateAccount(orig_command);
  auto serial_command = factory.deserializeCreateAccount(proto_command);
  ASSERT_EQ(orig_command, serial_command);
  command_converter_test(orig_command);
}

TEST(CommandTest, remove_signatory) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = iroha::model::RemoveSignatory();
  orig_command.account_id = "Vasya";
  std::fill(orig_command.pubkey.begin(), orig_command.pubkey.end(), 0xF);

  auto proto_command = factory.serializeRemoveSignatory(orig_command);
  auto serial_command = factory.deserializeRemoveSignatory(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

TEST(CommandTest, set_account_quorum) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = iroha::model::SetQuorum();
  orig_command.new_quorum = 11;
  orig_command.account_id = "Vasya";

  auto proto_command = factory.serializeSetQuorum(orig_command);
  auto serial_command = factory.deserializeSetQuorum(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

TEST(CommandTest, set_transfer_asset) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = iroha::model::TransferAsset();
  orig_command.amount = {120, 2};
  orig_command.asset_id = "tugrik";
  orig_command.src_account_id = "Vasya";
  orig_command.dest_account_id = "Petya";
  orig_command.description = "from Vasya to Petya without love";

  auto proto_command = factory.serializeTransferAsset(orig_command);
  auto serial_command = factory.deserializeTransferAsset(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

class TestablePbCommandFactory
    : public iroha::model::converters::PbCommandFactory {
 public:
  auto &getPermMap() {
    return pb_role_map_;
  }
};

TEST(CommandTest, create_role) {
  auto factory = iroha::model::converters::PbCommandFactory();
  std::set<std::string> perms;
  perms.insert(role_perm_group.begin(), role_perm_group.end());

  for (auto perm : perms) {
    TestablePbCommandFactory test_factory;
    auto map = test_factory.getPermMap();
    auto it = map.right.find(perm);
    ASSERT_NE(map.right.end(), it) << "On permission " << perm;
    std::set<std::string> tmp_perms = {perm};
    auto orig_command = CreateRole("master", tmp_perms);
    auto proto_command = factory.serializeCreateRole(orig_command);
    auto serial_command = factory.deserializeCreateRole(proto_command);
    ASSERT_EQ(orig_command, serial_command);
  }
  auto orig_command = CreateRole("master", perms);
  auto proto_command = factory.serializeCreateRole(orig_command);
  auto serial_command = factory.deserializeCreateRole(proto_command);
  ASSERT_EQ(orig_command, serial_command);
  command_converter_test(orig_command);
}

TEST(CommandTest, append_role) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = AppendRole("test@test", "master");

  auto proto_command = factory.serializeAppendRole(orig_command);
  auto serial_command = factory.deserializeAppendRole(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

TEST(CommandTest, detach_role) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = DetachRole("test@test", "master");

  auto proto_command = factory.serializeDetachRole(orig_command);
  auto serial_command = factory.deserializeDetachRole(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

TEST(CommandTest, grant_permission) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = GrantPermission("admin@test", can_add_signatory);

  auto proto_command = factory.serializeGrantPermission(orig_command);
  auto serial_command = factory.deserializeGrantPermission(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

TEST(CommandTest, revoke_permission) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = RevokePermission("admin@test", can_add_signatory);

  auto proto_command = factory.serializeRevokePermission(orig_command);
  auto serial_command = factory.deserializeRevokePermission(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}

TEST(CommandTest, set_account_detail) {
  auto factory = iroha::model::converters::PbCommandFactory();

  auto orig_command = SetAccountDetail("test@test", "key", "value");

  auto proto_command = factory.serializeSetAccountDetail(orig_command);
  auto serial_command = factory.deserializeSetAccountDetail(proto_command);

  ASSERT_EQ(orig_command, serial_command);

  command_converter_test(orig_command);
}
