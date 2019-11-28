/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_command.hpp"

#include "backend/protobuf/commands/proto_add_asset_quantity.hpp"
#include "backend/protobuf/commands/proto_add_peer.hpp"
#include "backend/protobuf/commands/proto_add_signatory.hpp"
#include "backend/protobuf/commands/proto_append_role.hpp"
#include "backend/protobuf/commands/proto_compare_and_set_account_detail.hpp"
#include "backend/protobuf/commands/proto_create_account.hpp"
#include "backend/protobuf/commands/proto_create_asset.hpp"
#include "backend/protobuf/commands/proto_create_domain.hpp"
#include "backend/protobuf/commands/proto_create_role.hpp"
#include "backend/protobuf/commands/proto_detach_role.hpp"
#include "backend/protobuf/commands/proto_grant_permission.hpp"
#include "backend/protobuf/commands/proto_remove_peer.hpp"
#include "backend/protobuf/commands/proto_remove_signatory.hpp"
#include "backend/protobuf/commands/proto_revoke_permission.hpp"
#include "backend/protobuf/commands/proto_set_account_detail.hpp"
#include "backend/protobuf/commands/proto_set_quorum.hpp"
#include "backend/protobuf/commands/proto_set_setting_value.hpp"
#include "backend/protobuf/commands/proto_subtract_asset_quantity.hpp"
#include "backend/protobuf/commands/proto_transfer_asset.hpp"
#include "commands.pb.h"
#include "common/variant_transform.hpp"

using namespace shared_model::proto;

using PbCommand = iroha::protocol::Command;

using ProtoCommandVariantType =
    iroha::VariantOfUniquePtr<AddAssetQuantity,
                              AddPeer,
                              AddSignatory,
                              AppendRole,
                              CreateAccount,
                              CreateAsset,
                              CreateDomain,
                              CreateRole,
                              DetachRole,
                              GrantPermission,
                              RemoveSignatory,
                              RevokePermission,
                              SetAccountDetail,
                              SetQuorum,
                              SubtractAssetQuantity,
                              TransferAsset,
                              RemovePeer,
                              CompareAndSetAccountDetail,
                              SetSettingValue>;

namespace {
  iroha::AggregateValueResult<ProtoCommandVariantType::types, std::string>
  loadCommandResult(PbCommand &pb_command) {
    switch (pb_command.command_case()) {
      case PbCommand::kAddAssetQuantity:
        return std::make_unique<AddAssetQuantity>(pb_command);
      case PbCommand::kAddPeer:
        return AddPeer::create(pb_command).variant();
      case PbCommand::kAddSignatory:
        return AddSignatory::create(pb_command).variant();
      case PbCommand::kAppendRole:
        return std::make_unique<AppendRole>(pb_command);
      case PbCommand::kCreateAccount:
        return CreateAccount::create(pb_command).variant();
      case PbCommand::kCreateAsset:
        return std::make_unique<CreateAsset>(pb_command);
      case PbCommand::kCreateDomain:
        return std::make_unique<CreateDomain>(pb_command);
      case PbCommand::kCreateRole:
        return std::make_unique<CreateRole>(pb_command);
      case PbCommand::kDetachRole:
        return std::make_unique<DetachRole>(pb_command);
      case PbCommand::kGrantPermission:
        return std::make_unique<GrantPermission>(pb_command);
      case PbCommand::kRemoveSignatory:
        return RemoveSignatory::create(pb_command).variant();
      case PbCommand::kRevokePermission:
        return std::make_unique<RevokePermission>(pb_command);
      case PbCommand::kSetAccountDetail:
        return std::make_unique<SetAccountDetail>(pb_command);
      case PbCommand::kSetAccountQuorum:
        return std::make_unique<SetQuorum>(pb_command);
      case PbCommand::kSubtractAssetQuantity:
        return std::make_unique<SubtractAssetQuantity>(pb_command);
      case PbCommand::kTransferAsset:
        return std::make_unique<TransferAsset>(pb_command);
      case PbCommand::kRemovePeer:
        return RemovePeer::create(pb_command).variant();
      case PbCommand::kCompareAndSetAccountDetail:
        return std::make_unique<CompareAndSetAccountDetail>(pb_command);
      case PbCommand::kSetSettingValue:
        return std::make_unique<SetSettingValue>(pb_command);
      default:
        return "Unknown command.";
    };
  }

  iroha::expected::Result<ProtoCommandVariantType, std::string> loadCommand(
      PbCommand &pb_command) {
    return loadCommandResult(pb_command);
  }
}  // namespace

struct Command::Impl {
  Impl(ProtoCommandVariantType command_holder)
      : command_holder_(std::move(command_holder)),
        command_constref_(boost::apply_visitor(
            iroha::indirecting_visitor<CommandVariantType>, command_holder_)) {}

  ProtoCommandVariantType command_holder_;
  CommandVariantType command_constref_;
};

iroha::expected::Result<std::unique_ptr<Command>, std::string> Command::create(
    TransportType &proto) {
  return loadCommand(proto) | [](auto &&command) {
    return std::unique_ptr<Command>(
        new Command(std::make_unique<Impl>(std::move(command))));
  };
}

Command::Command(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}

Command::~Command() = default;

const Command::CommandVariantType &Command::get() const {
  return impl_->command_constref_;
}
