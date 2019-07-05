/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMAND_MOCKS_HPP
#define IROHA_COMMAND_MOCKS_HPP

#include <gmock/gmock.h>
#include <boost/variant.hpp>
#include "cryptography/public_key.hpp"
#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/create_account.hpp"
#include "interfaces/commands/create_asset.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/create_role.hpp"
#include "interfaces/commands/detach_role.hpp"
#include "interfaces/commands/grant_permission.hpp"
#include "interfaces/commands/remove_signatory.hpp"
#include "interfaces/commands/revoke_permission.hpp"
#include "interfaces/commands/set_account_detail.hpp"
#include "interfaces/commands/set_quorum.hpp"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"
#include "logger/logger.hpp"

using testing::Return;

namespace shared_model {
  namespace interface {
    struct MockCommand : public Command {
      MOCK_CONST_METHOD0(get, const Command::CommandVariantType &());
    };

    struct SpecificMockCommandBase {};

    template <typename T>
    struct SpecificMockCommand : public T, public SpecificMockCommandBase {};

    struct MockAddAssetQuantity : public SpecificMockCommand<AddAssetQuantity> {
      MOCK_CONST_METHOD0(assetId, const types::AssetIdType &());
      MOCK_CONST_METHOD0(amount, const Amount &());
    };

    struct MockAddPeer : public SpecificMockCommand<AddPeer> {
      MOCK_CONST_METHOD0(peer, const Peer &());
    };

    struct MockAddSignatory : public SpecificMockCommand<AddSignatory> {
      MOCK_CONST_METHOD0(pubkey, const types::PubkeyType &());
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
    };

    struct MockAppendRole : public SpecificMockCommand<AppendRole> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(roleName, const types::RoleIdType &());
    };

    struct MockCreateAccount : public SpecificMockCommand<CreateAccount> {
      MOCK_CONST_METHOD0(accountName, const types::AccountNameType &());
      MOCK_CONST_METHOD0(domainId, const types::DomainIdType &());
      MOCK_CONST_METHOD0(pubkey, const types::PubkeyType &());
    };

    struct MockCreateAsset : public SpecificMockCommand<CreateAsset> {
      MOCK_CONST_METHOD0(assetName, const types::AssetNameType &());
      MOCK_CONST_METHOD0(domainId, const types::DomainIdType &());
      MOCK_CONST_METHOD0(precision, const PrecisionType &());
    };

    struct MockCreateDomain : public SpecificMockCommand<CreateDomain> {
      MOCK_CONST_METHOD0(domainId, const types::DomainIdType &());
      MOCK_CONST_METHOD0(userDefaultRole, const types::RoleIdType &());
    };

    struct MockCreateRole : public SpecificMockCommand<CreateRole> {
      MockCreateRole() {
        ON_CALL(*this, toString()).WillByDefault(Return("MockCreateRole"));
      }

      MOCK_CONST_METHOD0(roleName, const types::RoleIdType &());
      MOCK_CONST_METHOD0(rolePermissions, const RolePermissionSet &());
      MOCK_CONST_METHOD0(toString, std::string());
    };

    struct MockDetachRole : public SpecificMockCommand<DetachRole> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(roleName, const types::RoleIdType &());
    };

    struct MockGrantPermission : public SpecificMockCommand<GrantPermission> {
      MockGrantPermission() {
        ON_CALL(*this, toString())
            .WillByDefault(Return("MockGrantPermissions"));
      }

      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(permissionName, permissions::Grantable());
      MOCK_CONST_METHOD0(toString, std::string());
    };

    struct MockRemoveSignatory : public SpecificMockCommand<RemoveSignatory> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(pubkey, const types::PubkeyType &());
    };

    struct MockRevokePermission : public SpecificMockCommand<RevokePermission> {
      MockRevokePermission() {
        ON_CALL(*this, toString())
            .WillByDefault(Return("MockRevokePermission"));
      }

      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(permissionName, permissions::Grantable());
      MOCK_CONST_METHOD0(toString, std::string());
    };

    struct MockSetAccountDetail : public SpecificMockCommand<SetAccountDetail> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(key, const types::AccountDetailKeyType &());
      MOCK_CONST_METHOD0(value, const types::AccountDetailValueType &());
    };

    struct MockSetQuorum : public SpecificMockCommand<SetQuorum> {
      MOCK_CONST_METHOD0(accountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(newQuorum, types::QuorumType());
    };

    struct MockSubtractAssetQuantity
        : public SpecificMockCommand<SubtractAssetQuantity> {
      MOCK_CONST_METHOD0(assetId, const types::AssetIdType &());
      MOCK_CONST_METHOD0(amount, const Amount &());
    };

    struct MockTransferAsset : public SpecificMockCommand<TransferAsset> {
      MOCK_CONST_METHOD0(srcAccountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(destAccountId, const types::AccountIdType &());
      MOCK_CONST_METHOD0(assetId, const types::AssetIdType &());
      MOCK_CONST_METHOD0(amount, const Amount &());
      MOCK_CONST_METHOD0(description, const types::DescriptionType &());
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_COMMAND_MOCKS_HPP
