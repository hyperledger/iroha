/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PB_COMMAND_FACTORY_HPP
#define IROHA_PB_COMMAND_FACTORY_HPP

#include <primitive.pb.h>
#include <boost/bimap.hpp>
#include <unordered_map>
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
#include "model/commands/set_account_detail.hpp"
#include "model/commands/set_quorum.hpp"
#include "model/commands/subtract_asset_quantity.hpp"
#include "model/commands/transfer_asset.hpp"
#include "model/permissions.hpp"

namespace iroha {
  namespace model {
    namespace converters {

      /**
       * Converting commands and proto commands
       */
      class PbCommandFactory {
       public:
        PbCommandFactory();
        // asset quantity
        protocol::AddAssetQuantity serializeAddAssetQuantity(
            const model::AddAssetQuantity &addAssetQuantity);
        model::AddAssetQuantity deserializeAddAssetQuantity(
            const protocol::AddAssetQuantity &addAssetQuantity);

        // subtract asset quantity
        protocol::SubtractAssetQuantity serializeSubtractAssetQuantity(
            const model::SubtractAssetQuantity &subtractAssetQuantity);
        model::SubtractAssetQuantity deserializeSubtractAssetQuantity(
            const protocol::SubtractAssetQuantity &subtractAssetQuantity);

        // add peer
        protocol::AddPeer serializeAddPeer(const model::AddPeer &addPeer);
        model::AddPeer deserializeAddPeer(const protocol::AddPeer &addPeer);

        // add signatory
        protocol::AddSignatory serializeAddSignatory(
            const model::AddSignatory &addSignatory);
        model::AddSignatory deserializeAddSignatory(
            const protocol::AddSignatory &addSignatory);

        // create asset
        protocol::CreateAsset serializeCreateAsset(
            const model::CreateAsset &createAsset);
        model::CreateAsset deserializeCreateAsset(
            const protocol::CreateAsset &createAsset);

        // create account
        protocol::CreateAccount serializeCreateAccount(
            const model::CreateAccount &createAccount);
        model::CreateAccount deserializeCreateAccount(
            const protocol::CreateAccount &createAccount);

        // create domain
        protocol::CreateDomain serializeCreateDomain(
            const model::CreateDomain &createDomain);
        model::CreateDomain deserializeCreateDomain(
            const protocol::CreateDomain &createDomain);

        // remove signatory
        protocol::RemoveSignatory serializeRemoveSignatory(
            const model::RemoveSignatory &removeSignatory);
        model::RemoveSignatory deserializeRemoveSignatory(
            const protocol::RemoveSignatory &removeSignatory);

        // set account quorum
        protocol::SetAccountQuorum serializeSetQuorum(
            const model::SetQuorum &setAccountQuorum);
        model::SetQuorum deserializeSetQuorum(
            const protocol::SetAccountQuorum &setAccountQuorum);

        // transfer asset
        protocol::TransferAsset serializeTransferAsset(
            const model::TransferAsset &subtractAssetQuantity);
        model::TransferAsset deserializeTransferAsset(
            const protocol::TransferAsset &subtractAssetQuantity);

        // Append role
        protocol::AppendRole serializeAppendRole(
            const model::AppendRole &command);
        model::AppendRole deserializeAppendRole(
            const protocol::AppendRole &command);

        // Append role
        protocol::DetachRole serializeDetachRole(
            const model::DetachRole &command);
        model::DetachRole deserializeDetachRole(
            const protocol::DetachRole &command);

        // Create Role
        protocol::CreateRole serializeCreateRole(
            const model::CreateRole &command);
        model::CreateRole deserializeCreateRole(
            const protocol::CreateRole &command);

        // Grant Permission
        protocol::GrantPermission serializeGrantPermission(
            const model::GrantPermission &command);
        model::GrantPermission deserializeGrantPermission(
            const protocol::GrantPermission &command);

        // Revoke Permission
        protocol::RevokePermission serializeRevokePermission(
            const model::RevokePermission &command);
        model::RevokePermission deserializeRevokePermission(
            const protocol::RevokePermission &command);

        // Set Account Detail
        protocol::SetAccountDetail serializeSetAccountDetail(
            const model::SetAccountDetail &command);
        model::SetAccountDetail deserializeSetAccountDetail(
            const protocol::SetAccountDetail &command);

        // abstract
        protocol::Command serializeAbstractCommand(
            const model::Command &command);
        std::shared_ptr<model::Command> deserializeAbstractCommand(
            const protocol::Command &command);

       protected:
        boost::bimap<iroha::protocol::RolePermission, std::string> pb_role_map_;
        boost::bimap<iroha::protocol::GrantablePermission, std::string>
            pb_grant_map_;
      };
    }  // namespace converters
  }    // namespace model
}  // namespace iroha
#endif  // IROHA_PB_COMMAND_FACTORY_HPP
