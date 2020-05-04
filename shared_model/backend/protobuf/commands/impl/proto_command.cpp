/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_command.hpp"

#include "backend/protobuf/commands/proto_add_asset_quantity.hpp"
#include "backend/protobuf/commands/proto_add_peer.hpp"
#include "backend/protobuf/commands/proto_add_signatory.hpp"
#include "backend/protobuf/commands/proto_add_smart_contract.hpp"
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
#include "utils/variant_deserializer.hpp"

namespace {
  /// type of proto variant
  using ProtoCommandVariantType =
      ::boost::variant<shared_model::proto::AddAssetQuantity,
                       shared_model::proto::AddPeer,
                       shared_model::proto::AddSignatory,
                       shared_model::proto::AddSmartContract,
                       shared_model::proto::AppendRole,
                       shared_model::proto::CreateAccount,
                       shared_model::proto::CreateAsset,
                       shared_model::proto::CreateDomain,
                       shared_model::proto::CreateRole,
                       shared_model::proto::DetachRole,
                       shared_model::proto::GrantPermission,
                       shared_model::proto::RemoveSignatory,
                       shared_model::proto::RevokePermission,
                       shared_model::proto::SetAccountDetail,
                       shared_model::proto::SetQuorum,
                       shared_model::proto::SubtractAssetQuantity,
                       shared_model::proto::TransferAsset,
                       shared_model::proto::RemovePeer,
                       shared_model::proto::CompareAndSetAccountDetail,
                       shared_model::proto::SetSettingValue>;

  /// list of types in proto variant
  using ProtoCommandListType = ProtoCommandVariantType::types;
}  // namespace

namespace shared_model {
  namespace proto {

    struct Command::Impl {
      explicit Impl(TransportType &ref) : proto_(ref) {}

      TransportType &proto_;

      ProtoCommandVariantType variant_{[this] {
        auto &ar = proto_;
        int which =
            ar.GetDescriptor()->FindFieldByNumber(ar.command_case())->index();
        return shared_model::detail::variant_impl<ProtoCommandListType>::
            template load<ProtoCommandVariantType>(ar, which);
      }()};

      CommandVariantType ivariant_{variant_};
    };

    Command::Command(TransportType &ref) {
      impl_ = std::make_unique<Impl>(ref);
    }

    Command::~Command() = default;

    const Command::CommandVariantType &Command::get() const {
      return impl_->ivariant_;
    }

  }  // namespace proto
}  // namespace shared_model
