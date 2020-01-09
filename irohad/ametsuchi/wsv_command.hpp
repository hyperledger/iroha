/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_WSV_COMMAND_HPP
#define IROHA_WSV_COMMAND_HPP

#include <set>
#include <string>

#include "common/result.hpp"
#include "interfaces/common_objects/string_view_types.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"

namespace shared_model {
  namespace interface {
    class Asset;
    class Account;
    class Domain;
    class Peer;
    class AccountAsset;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  struct TopBlockInfo;

  namespace ametsuchi {

    /**
     * Error returned by wsv command.
     * It is a string which contains what action has failed (e.g, "failed to
     * insert role"), and an error which was provided by underlying
     * implementation (e.g, database exception info)
     */
    using WsvError = std::string;

    /**
     *  If command is successful, we assume changes are made,
     *  and do not need anything
     *  If something goes wrong, Result will contain WsvError
     *  with additional information
     */
    using WsvCommandResult = expected::Result<void, WsvError>;

    /**
     * Commands for modifying world state view
     */
    class WsvCommand {
     public:
      virtual ~WsvCommand() = default;

      /**
       * Insert role entity
       * @param role_name
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertRole(
          const shared_model::interface::types::RoleIdType &role_name) = 0;

      /**
       * Bind account and role
       * @param account_id
       * @param role_name
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertAccountRole(
          const shared_model::interface::types::AccountIdType &account_id,
          const shared_model::interface::types::RoleIdType &role_name) = 0;
      /**
       * Unbind account and role
       * @param account_id
       * @param role_name
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult deleteAccountRole(
          const shared_model::interface::types::AccountIdType &account_id,
          const shared_model::interface::types::RoleIdType &role_name) = 0;

      /**
       * Bind role and permissions
       * @param role_id
       * @param permissions
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertRolePermissions(
          const shared_model::interface::types::RoleIdType &role_id,
          const shared_model::interface::RolePermissionSet &permissions) = 0;

      /**
       * Insert grantable permission
       * @param permittee_account_id to who give the grant permission
       * @param account_id on which account
       * @param permission what permission
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertAccountGrantablePermission(
          const shared_model::interface::types::AccountIdType
              &permittee_account_id,
          const shared_model::interface::types::AccountIdType &account_id,
          shared_model::interface::permissions::Grantable permission) = 0;

      /**
       * Delete grantable permission
       * @param permittee_account_id to who the grant permission was previously
       * granted
       * @param account_id on which account
       * @param permission what permission
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult deleteAccountGrantablePermission(
          const shared_model::interface::types::AccountIdType
              &permittee_account_id,
          const shared_model::interface::types::AccountIdType &account_id,
          shared_model::interface::permissions::Grantable permission) = 0;

      /**
       *git
       * @param account
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertAccount(
          const shared_model::interface::Account &account) = 0;

      /**
       *
       * @param account
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult updateAccount(
          const shared_model::interface::Account &account) = 0;

      /**
       * @param account_id  account in which update key value
       * @param creator_account_id creator's account who wants to update
       * account_id
       * @param key - key to set
       * @param val - value of the key/value pair
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult setAccountKV(
          const shared_model::interface::types::AccountIdType &account_id,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &key,
          const std::string &val) = 0;

      /**
       *
       * @param asset
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertAsset(
          const shared_model::interface::Asset &asset) = 0;

      /**
       * Update or insert account asset
       * @param asset
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult upsertAccountAsset(
          const shared_model::interface::AccountAsset &asset) = 0;

      /**
       *
       * @param signatory
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertSignatory(
          shared_model::interface::types::PublicKeyHexStringView signatory) = 0;

      /**
       * Insert account signatory relationship
       * @param account_id
       * @param signatory
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertAccountSignatory(
          const shared_model::interface::types::AccountIdType &account_id,
          shared_model::interface::types::PublicKeyHexStringView signatory) = 0;

      /**
       * Delete account signatory relationship
       * @param account_id
       * @param signatory
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult deleteAccountSignatory(
          const shared_model::interface::types::AccountIdType &account_id,
          shared_model::interface::types::PublicKeyHexStringView signatory) = 0;

      /**
       * Delete signatory
       * @param signatory
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult deleteSignatory(
          shared_model::interface::types::PublicKeyHexStringView signatory) = 0;

      /**
       *
       * @param peer
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertPeer(
          const shared_model::interface::Peer &peer) = 0;

      /**
       *
       * @param peer
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult deletePeer(
          const shared_model::interface::Peer &peer) = 0;

      /**
       *
       * @param peer
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult insertDomain(
          const shared_model::interface::Domain &domain) = 0;

      /**
       * Set the top block info in ledger state.
       * @param top_block_info the info to be written to wsv
       * @return WsvCommandResult, which will contain error in case of failure
       */
      virtual WsvCommandResult setTopBlockInfo(
          const TopBlockInfo &top_block_info) const = 0;
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_WSV_COMMAND_HPP
