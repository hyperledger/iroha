/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMAND_MOCKS_HPP
#define IROHA_COMMAND_MOCKS_HPP

#include <gmock/gmock.h>
#include <boost/variant.hpp>
#include <optional>
#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/compare_and_set_account_detail.hpp"
#include "interfaces/commands/create_account.hpp"
#include "interfaces/commands/create_asset.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/create_role.hpp"
#include "interfaces/commands/detach_role.hpp"
#include "interfaces/commands/grant_permission.hpp"
#include "interfaces/commands/remove_peer.hpp"
#include "interfaces/commands/remove_signatory.hpp"
#include "interfaces/commands/revoke_permission.hpp"
#include "interfaces/commands/set_account_detail.hpp"
#include "interfaces/commands/set_quorum.hpp"
#include "interfaces/commands/set_setting_value.hpp"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"

using testing::Return;

namespace shared_model {
  namespace interface {
    struct MockCommand : public shared_model::interface::Command {
      MOCK_CONST_METHOD0(get, const Command::CommandVariantType &());
    };

    struct MockAddAssetQuantity
        : public shared_model::interface::AddAssetQuantity {
      MOCK_CONST_METHOD0(assetId, const types::AssetIdType &());
      MOCK_CONST_METHOD0(amount, const Amount &());
      MOCK_CONST_METHOD0(description, const std::string &());
    };

    struct MockAddPeer : public shared_model::interface::AddPeer {
      MOCK_CONST_METHOD0(peer, const Peer &());
    };

    struct MockRemovePeer : public shared_model::interface::RemovePeer {
      MOCK_CONST_METHOD0(pubkey, const std::string &());
    };

    struct MockAddSignatory : public shared_model::interface::AddSignatory {
      MOCK_CONST_METHOD0(pubkey, const std::string &());
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
    };

    struct MockAppendRole : public shared_model::interface::AppendRole {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(roleName, const types::RoleIdType &());
    };

    struct MockCreateAccount : public shared_model::interface::CreateAccount {
      MOCK_CONST_METHOD0(accountName, const types::AccountNameType &());
      MOCK_CONST_METHOD0(domainId, const types::DomainIdType &());
      MOCK_CONST_METHOD0(pubkey, const std::string &());
    };

    struct MockCreateAsset : public shared_model::interface::CreateAsset {
      MOCK_CONST_METHOD0(assetName, const types::AssetNameType &());
      MOCK_CONST_METHOD0(domainId, const types::DomainIdType &());
      MOCK_CONST_METHOD0(precision, const PrecisionType &());
    };

    struct MockCreateDomain : public shared_model::interface::CreateDomain {
      MOCK_CONST_METHOD0(domainId, const types::DomainIdType &());
      MOCK_CONST_METHOD0(userDefaultRole, const types::RoleIdType &());
    };

    struct MockCreateRole : public shared_model::interface::CreateRole {
      MockCreateRole() {
        ON_CALL(*this, toString()).WillByDefault(Return("MockCreateRole"));
      }

      MOCK_CONST_METHOD0(roleName, const types::RoleIdType &());
      MOCK_CONST_METHOD0(rolePermissions, const RolePermissionSet &());
      MOCK_CONST_METHOD0(toString, std::string());
    };

    struct MockDetachRole : public shared_model::interface::DetachRole {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(roleName, const types::RoleIdType &());
    };

    struct MockGrantPermission
        : public shared_model::interface::GrantPermission {
      MockGrantPermission() {
        ON_CALL(*this, toString())
            .WillByDefault(Return("MockGrantPermissions"));
      }

      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(permissionName, permissions::Grantable());
      MOCK_CONST_METHOD0(toString, std::string());
    };

    struct MockRemoveSignatory
        : public shared_model::interface::RemoveSignatory {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(pubkey, const std::string &());
    };

    struct MockRevokePermission
        : public shared_model::interface::RevokePermission {
      MockRevokePermission() {
        ON_CALL(*this, toString())
            .WillByDefault(Return("MockRevokePermission"));
      }

      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(permissionName, permissions::Grantable());
      MOCK_CONST_METHOD0(toString, std::string());
    };

    struct MockSetAccountDetail
        : public shared_model::interface::SetAccountDetail {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(key, const types::AccountDetailKeyType &());
      MOCK_CONST_METHOD0(value, const types::AccountDetailValueType &());
    };

    struct MockSetQuorum : public shared_model::interface::SetQuorum {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(newQuorum, types::QuorumType());
    };

    struct MockSubtractAssetQuantity
        : public shared_model::interface::SubtractAssetQuantity {
      MOCK_CONST_METHOD0(assetId, const types::AssetIdType &());
      MOCK_CONST_METHOD0(amount, const Amount &());
      MOCK_CONST_METHOD0(description, const std::string &());
    };

    struct MockTransferAsset : public shared_model::interface::TransferAsset {
      MOCK_CONST_METHOD0(srcAccountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(destAccountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(assetId, const types::AssetIdType &());
      MOCK_CONST_METHOD0(amount, const Amount &());
      MOCK_CONST_METHOD0(description, const types::DescriptionType &());
    };

    struct MockCompareAndSetAccountDetail
        : public shared_model::interface::CompareAndSetAccountDetail {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(key, const types::AccountDetailKeyType &());
      MOCK_CONST_METHOD0(value, const types::AccountDetailValueType &());
      MOCK_CONST_METHOD0(checkEmpty, bool());
      MOCK_CONST_METHOD0(oldValue,
                         const std::optional<types::AccountDetailValueType>());
    };

    struct MockSetSettingValue
        : public shared_model::interface::SetSettingValue {
      MOCK_CONST_METHOD0(key, const types::SettingKeyType &());
      MOCK_CONST_METHOD0(value, const types::SettingValueType &());
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_COMMAND_MOCKS_HPP
