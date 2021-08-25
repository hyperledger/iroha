/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_command.hpp"

#include "backend/protobuf/commands/proto_add_asset_quantity.hpp"
#include "backend/protobuf/commands/proto_add_peer.hpp"
#include "backend/protobuf/commands/proto_add_signatory.hpp"
#include "backend/protobuf/commands/proto_append_role.hpp"
#include "backend/protobuf/commands/proto_call_engine.hpp"
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
#include "common/report_abort.h"

namespace {
  /// type of proto variant
  using ProtoCommandVariantType =
      ::boost::variant<shared_model::proto::AddAssetQuantity,
                       shared_model::proto::AddPeer,
                       shared_model::proto::AddSignatory,
                       shared_model::proto::AppendRole,
                       shared_model::proto::CallEngine,
                       shared_model::proto::CompareAndSetAccountDetail,
                       shared_model::proto::CreateAccount,
                       shared_model::proto::CreateAsset,
                       shared_model::proto::CreateDomain,
                       shared_model::proto::CreateRole,
                       shared_model::proto::DetachRole,
                       shared_model::proto::GrantPermission,
                       shared_model::proto::RemovePeer,
                       shared_model::proto::RemoveSignatory,
                       shared_model::proto::RevokePermission,
                       shared_model::proto::SetAccountDetail,
                       shared_model::proto::SetQuorum,
                       shared_model::proto::SetSettingValue,
                       shared_model::proto::SubtractAssetQuantity,
                       shared_model::proto::TransferAsset>;
}  // namespace

#ifdef IROHA_BIND_TYPE
#error IROHA_BIND_TYPE defined.
#endif  // IROHA_BIND_TYPE
#define IROHA_BIND_TYPE(val, type, ...)            \
  case iroha::protocol::Command::CommandCase::val: \
    return ProtoCommandVariantType(shared_model::proto::type(__VA_ARGS__))

namespace shared_model::proto {

  struct Command::Impl {
    explicit Impl(TransportType &ref) : proto_(ref) {}

    TransportType &proto_;

    ProtoCommandVariantType variant_{[this]() -> decltype(variant_) {
      auto &ar = proto_;

      switch (ar.command_case()) {
        IROHA_BIND_TYPE(kAddAssetQuantity, AddAssetQuantity, ar);
        IROHA_BIND_TYPE(kAddPeer, AddPeer, ar);
        IROHA_BIND_TYPE(kAddSignatory, AddSignatory, ar);
        IROHA_BIND_TYPE(kAppendRole, AppendRole, ar);
        IROHA_BIND_TYPE(kCreateAccount, CreateAccount, ar);
        IROHA_BIND_TYPE(kCreateAsset, CreateAsset, ar);
        IROHA_BIND_TYPE(kCreateDomain, CreateDomain, ar);
        IROHA_BIND_TYPE(kCreateRole, CreateRole, ar);
        IROHA_BIND_TYPE(kDetachRole, DetachRole, ar);
        IROHA_BIND_TYPE(kGrantPermission, GrantPermission, ar);
        IROHA_BIND_TYPE(kRemovePeer, RemovePeer, ar);
        IROHA_BIND_TYPE(kRemoveSignatory, RemoveSignatory, ar);
        IROHA_BIND_TYPE(kRevokePermission, RevokePermission, ar);
        IROHA_BIND_TYPE(kSetAccountDetail, SetAccountDetail, ar);
        IROHA_BIND_TYPE(kSetAccountQuorum, SetQuorum, ar);
        IROHA_BIND_TYPE(kSubtractAssetQuantity, SubtractAssetQuantity, ar);
        IROHA_BIND_TYPE(kTransferAsset, TransferAsset, ar);
        IROHA_BIND_TYPE(
            kCompareAndSetAccountDetail, CompareAndSetAccountDetail, ar);
        IROHA_BIND_TYPE(kSetSettingValue, SetSettingValue, ar);
        IROHA_BIND_TYPE(kCallEngine, CallEngine, ar);

        default:
        case iroha::protocol::Command::CommandCase::COMMAND_NOT_SET:
          report_abort("Unexpected command case.");
      };
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

}  // namespace shared_model::proto

#undef IROHA_BIND_TYPE
