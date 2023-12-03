/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_COMMAND_FACTORY_HPP
#define IROHA_MOCK_COMMAND_FACTORY_HPP

#include "interfaces/common_objects/string_view_types.hpp"
#include "module/shared_model/command_mocks.hpp"

namespace shared_model {
  namespace interface {
    class MockCommandFactory {
      template <typename T>
      using FactoryResult = std::unique_ptr<T>;

     public:
      /**
       * Construct a mocked AddAssetQuantity
       * @param asset_id to be in that command
       * @param asset_amount to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockAddAssetQuantity> constructAddAssetQuantity(
          const types::AssetIdType &asset_id, const Amount &asset_amount) const;

      FactoryResult<MockAddAssetQuantity> constructAddAssetQuantityWithDescription(
          const types::AssetIdType &asset_id, const Amount &asset_amount, const std::string &description) const;

      /**
       * Construct a mocked AddPeer
       * @param peer to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockAddPeer> constructAddPeer(const Peer &peer) const;

      /**
       * Construct a mocked RemovePeer
       * @param pubkey to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockRemovePeer> constructRemovePeer(
          types::PublicKeyHexStringView pubkey) const;

      /**
       * Construct a mocked AddSignatory
       * @param pubkey to be in that command
       * @param account_id to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockAddSignatory> constructAddSignatory(
          types::PublicKeyHexStringView pubkey,
          const types::AccountIdType &account_id) const;

      /**
       * Construct a mocked AppendRole
       * @param account_id to be in that command
       * @param role_name to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockAppendRole> constructAppendRole(
          const types::AccountIdType &account_id,
          const types::RoleIdType &role_name) const;

      /**
       * Construct a mocked CreateAccount
       * @param account_name to be in that command
       * @param domain_id to be in that command
       * @param pubkey to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockCreateAccount> constructCreateAccount(
          const types::AccountNameType &account_name,
          const types::DomainIdType &domain_id,
          types::PublicKeyHexStringView pubkey) const;

      /**
       * Construct a mocked CreateAsset
       * @param asset_name to be in that command
       * @param domain_id to be in that command
       * @param precision to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockCreateAsset> constructCreateAsset(
          const types::AssetNameType &asset_name,
          const types::DomainIdType &domain_id,
          const types::PrecisionType &precision) const;

      /**
       * Construct a mocked CreateDomain
       * @param domain_id to be in that command
       * @param role_id to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockCreateDomain> constructCreateDomain(
          const types::DomainIdType &domain_id,
          const types::RoleIdType &role_id) const;

      /**
       * Construct a mocked CreateRole
       * @param role_id to be in that command
       * @param role_permissions to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockCreateRole> constructCreateRole(
          const types::RoleIdType &role_id,
          const RolePermissionSet &role_permissions) const;

      /**
       * Construct a mocked DetachRole
       * @param account_id to be in that command
       * @param role_id to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockDetachRole> constructDetachRole(
          const types::AccountIdType &account_id,
          const types::RoleIdType &role_id) const;

      /**
       * Construct a mocked GrantPermission
       * @param account_id to be in that command
       * @param permission to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockGrantPermission> constructGrantPermission(
          const types::AccountIdType &account_id,
          permissions::Grantable permission) const;

      /**
       * Construct a mocked RemoveSignatory
       * @param account_id to be in that command
       * @param pubkey to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockRemoveSignatory> constructRemoveSignatory(
          const types::AccountIdType &account_id,
          types::PublicKeyHexStringView pubkey) const;

      /**
       * Construct a mocked RevokePermission
       * @param account_id to be in that command
       * @param permission to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockRevokePermission> constructRevokePermission(
          const types::AccountIdType &account_id,
          permissions::Grantable permission) const;

      /**
       * Construct a mocked SetAccountDetail
       * @param account_id to be in that command
       * @param key to be in that command
       * @param value to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockSetAccountDetail> constructSetAccountDetail(
          const types::AccountIdType &account_id,
          const types::AccountDetailKeyType &key,
          const types::AccountDetailValueType &value) const;

      /**
       * Construct a mocked SetQuorum
       * @param account_id to be in that command
       * @param quorum to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockSetQuorum> constructSetQuorum(
          const types::AccountIdType &account_id,
          types::QuorumType quorum) const;

      /**
       * Construct a mocked SubtractAssetQuantity
       * @param asset_id to be in that command
       * @param amount to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockSubtractAssetQuantity> constructSubtractAssetQuantity(
          const types::AssetIdType &asset_id, const Amount &amount) const;


      /**
       * Construct a mocked SubtractAssetQuantity
       * @param asset_id to be in that command
       * @param amount to be in that command
       * @param description to be in that comand
       * @return pointer to the created command
       */
      FactoryResult<MockSubtractAssetQuantity> constructSubtractAssetQuantityWithDescription(
          const types::AssetIdType &asset_id, const Amount &amount, const std::string &description) const;

      /**
       * Construct a mocked TransferAsset
       * @param src_account_id to be in that command
       * @param dest_account_id to be in that command
       * @param asset_id to be in that command
       * @param description to be in that command
       * @param amount to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockTransferAsset> constructTransferAsset(
          const types::AccountIdType &src_account_id,
          const types::AccountIdType &dest_account_id,
          const types::AssetIdType &asset_id,
          const types::DescriptionType &description,
          const Amount &amount) const;

      /**
       * Construct a mocked CompareAndSetAccountDetail
       * @param account_id to be in that command
       * @param key to be in that command
       * @param value to be in that command
       * @param old_value to be in that command
       * @param check_empty to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockCompareAndSetAccountDetail>
      constructCompareAndSetAccountDetail(
          const types::AccountIdType &account_id,
          const types::AccountDetailKeyType &key,
          const types::AccountDetailValueType &value,
          const std::optional<types::AccountDetailValueType> old_value,
          bool check_empty) const;

      /**
       * Construct a mocked SetSettingValue
       * @param key to be in that command
       * @param value to be in that command
       * @return pointer to the created command
       */
      FactoryResult<MockSetSettingValue> constructSetSettingValue(
          const types::SettingKeyType &key,
          const types::SettingValueType &value) const;

     private:
      /**
       * Actually create a pointer to the mocked command
       * @tparam CommandType - type of the command to be mocked
       * @tparam ExpectsCallable - type of callable, which contains necessary
       * EXPECT-s statements
       * @param callable - that callable
       * @return pointer to the mocked command
       */
      template <typename CommandType, typename ExpectsCallable>
      FactoryResult<CommandType> createFactoryResult(
          ExpectsCallable callable) const;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_MOCK_COMMAND_FACTORY_HPP
