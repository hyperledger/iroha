/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/converters/pb_command_factory.hpp"

#include <boost/assign/list_inserter.hpp>

#include "common/byteutils.hpp"
#include "common/instanceof.hpp"
#include "model/converters/pb_common.hpp"

using namespace shared_model::permissions;

namespace iroha {
  namespace model {
    namespace converters {

      /**
       * convert hex string to pubkey
       * @param dest reference to destination public key
       * @param src source string
       */
      static void trySetHexKey(pubkey_t &dest, const std::string &src) {
        iroha::hexstringToArray<pubkey_t::size()>(src) |
            [&dest](const auto &blob) { dest = blob; };
      }

      PbCommandFactory::PbCommandFactory() {
        boost::assign::insert(pb_role_map_)
            // Can append role
            (protocol::RolePermission::can_append_role, can_append_role)
            // Can create role
            (protocol::RolePermission::can_create_role, can_create_role)
            // Can append role
            (protocol::RolePermission::can_detach_role, can_detach_role)
            // Can add asset quantity
            (protocol::RolePermission::can_add_asset_qty, can_add_asset_qty)
            // Can subtract asset quantity
            (protocol::RolePermission::can_subtract_asset_qty,
             can_subtract_asset_qty)
            // Can add peer
            (protocol::RolePermission::can_add_peer, can_add_peer)
            // Can add signatory
            (protocol::RolePermission::can_add_signatory, can_add_signatory)
            // Can remove signatory
            (protocol::RolePermission::can_remove_signatory,
             can_remove_signatory)
            // Can set quorum
            (protocol::RolePermission::can_set_quorum, can_set_quorum)
            // Can create account
            (protocol::RolePermission::can_create_account, can_create_account)
            // Can set detail
            (protocol::RolePermission::can_set_detail, can_set_detail)
            // Can create asset
            (protocol::RolePermission::can_create_asset, can_create_asset)
            // Can transfer
            (protocol::RolePermission::can_transfer, can_transfer)
            // Can receive
            (protocol::RolePermission::can_receive, can_receive)
            // Can create domain
            (protocol::RolePermission::can_create_domain, can_create_domain)
            // Can read assets
            (protocol::RolePermission::can_read_assets, can_read_assets)
            // Can get roles
            (protocol::RolePermission::can_get_roles, can_get_roles)
            // Can get my account
            (protocol::RolePermission::can_get_my_account, can_get_my_account)
            // Can get all accounts
            (protocol::RolePermission::can_get_all_accounts,
             can_get_all_accounts)
            // Can get domain accounts
            (protocol::RolePermission::can_get_domain_accounts,
             can_get_domain_accounts)
            // Can get my signatories
            (protocol::RolePermission::can_get_my_signatories,
             can_get_my_signatories)
            // Can get all signatories
            (protocol::RolePermission::can_get_all_signatories,
             can_get_all_signatories)
            // Can get my engine receipts.
            (protocol::RolePermission::can_get_my_engine_receipts,
             can_get_my_engine_receipts)
            // Can get domain engine receipts.
            (protocol::RolePermission::can_get_domain_engine_receipts,
             can_get_domain_engine_receipts)
            // Can get all engine receipts.
            (protocol::RolePermission::can_get_all_engine_receipts,
             can_get_all_engine_receipts)
            // Can get domain signatories
            (protocol::RolePermission::can_get_domain_signatories,
             can_get_domain_signatories)
            // Can get my account assets
            (protocol::RolePermission::can_get_my_acc_ast, can_get_my_acc_ast)
            // Can get all account assets
            (protocol::RolePermission::can_get_all_acc_ast, can_get_all_acc_ast)
            // Can get domain account assets
            (protocol::RolePermission::can_get_domain_acc_ast,
             can_get_domain_acc_ast)
            // Can get my account detail
            (protocol::RolePermission::can_get_my_acc_detail,
             can_get_my_acc_detail)
            // Can get all account detail
            (protocol::RolePermission::can_get_all_acc_detail,
             can_get_all_acc_detail)
            // Can get domain account detail
            (protocol::RolePermission::can_get_domain_acc_detail,
             can_get_domain_acc_detail)
            // Can get my account transactions
            (protocol::RolePermission::can_get_my_acc_txs, can_get_my_acc_txs)
            // Can get all account transactions
            (protocol::RolePermission::can_get_all_acc_txs, can_get_all_acc_txs)
            // Can get domain account transactions
            (protocol::RolePermission::can_get_domain_acc_txs,
             can_get_domain_acc_txs)
            // Can get my account assets transactions
            (protocol::RolePermission::can_get_my_acc_ast_txs,
             can_get_my_acc_ast_txs)
            // Can get all account asset transactions
            (protocol::RolePermission::can_get_all_acc_ast_txs,
             can_get_all_acc_ast_txs)
            // Can get domain account asset transactions
            (protocol::RolePermission::can_get_domain_acc_ast_txs,
             can_get_domain_acc_ast_txs)
            // Can get my transactions
            (protocol::RolePermission::can_get_my_txs, can_get_my_txs)
            // Can get all transactions
            (protocol::RolePermission::can_get_all_txs, can_get_all_txs)

            // Can grant set quorum
            (protocol::RolePermission::can_grant_can_set_my_quorum,
             can_grant + can_set_my_quorum)
            // Can grant add signatory
            (protocol::RolePermission::can_grant_can_add_my_signatory,
             can_grant + can_add_my_signatory)
            // Can grant remove signatory
            (protocol::RolePermission::can_grant_can_remove_my_signatory,
             can_grant + can_remove_my_signatory)
            // Can grant can_transfer
            (protocol::RolePermission::can_grant_can_transfer_my_assets,
             can_grant + can_transfer_my_assets)
            // Can write details to other accounts
            (protocol::RolePermission::can_grant_can_set_my_account_detail,
             can_grant + can_set_my_account_detail)

            // Can get blocks
            (protocol::RolePermission::can_get_blocks, can_get_blocks);

        boost::assign::insert(pb_grant_map_)
            // Can add my signatory
            (protocol::GrantablePermission::can_add_my_signatory,
             can_add_signatory)
            // Can remove my signatory
            (protocol::GrantablePermission::can_remove_my_signatory,
             can_remove_signatory)
            // Can set my quorum
            (protocol::GrantablePermission::can_set_my_quorum, can_set_quorum)
            // Can write details to other accounts
            (protocol::GrantablePermission::can_set_my_account_detail,
             can_set_detail)
            // Can transfer my assets
            (protocol::GrantablePermission::can_transfer_my_assets,
             can_transfer);
      }

      // asset quantity
      protocol::AddAssetQuantity PbCommandFactory::serializeAddAssetQuantity(
          const model::AddAssetQuantity &add_asset_quantity) {
        protocol::AddAssetQuantity pb_add_asset_quantity;
        pb_add_asset_quantity.set_asset_id(add_asset_quantity.asset_id);
        pb_add_asset_quantity.set_amount(add_asset_quantity.amount);
        return pb_add_asset_quantity;
      }

      model::AddAssetQuantity PbCommandFactory::deserializeAddAssetQuantity(
          const protocol::AddAssetQuantity &pb_add_asset_quantity) {
        model::AddAssetQuantity add_asset_quantity;
        add_asset_quantity.asset_id = pb_add_asset_quantity.asset_id();
        add_asset_quantity.amount = pb_add_asset_quantity.amount();

        return add_asset_quantity;
      }

      // subtract asset quantity
      protocol::SubtractAssetQuantity
      PbCommandFactory::serializeSubtractAssetQuantity(
          const model::SubtractAssetQuantity &subtract_asset_quantity) {
        protocol::SubtractAssetQuantity pb_subtract_asset_quantity;
        pb_subtract_asset_quantity.set_asset_id(
            subtract_asset_quantity.asset_id);
        pb_subtract_asset_quantity.set_amount(subtract_asset_quantity.amount);
        return pb_subtract_asset_quantity;
      }

      model::SubtractAssetQuantity
      PbCommandFactory::deserializeSubtractAssetQuantity(
          const protocol::SubtractAssetQuantity &pb_subtract_asset_quantity) {
        model::SubtractAssetQuantity subtract_asset_quantity;
        subtract_asset_quantity.asset_id =
            pb_subtract_asset_quantity.asset_id();
        subtract_asset_quantity.amount = pb_subtract_asset_quantity.amount();
        subtract_asset_quantity.description = pb_subtract_asset_quantity.description();
        return subtract_asset_quantity;
      }

      // add peer
      protocol::AddPeer PbCommandFactory::serializeAddPeer(
          const model::AddPeer &add_peer) {
        protocol::AddPeer pb_add_peer;
        auto peer = pb_add_peer.mutable_peer();
        peer->CopyFrom(serializePeer(add_peer.peer));
        return pb_add_peer;
      }

      model::AddPeer PbCommandFactory::deserializeAddPeer(
          const protocol::AddPeer &pb_add_peer) {
        model::AddPeer add_peer;
        add_peer.peer = deserializePeer(pb_add_peer.peer());

        return add_peer;
      }

      // add signatory
      protocol::AddSignatory PbCommandFactory::serializeAddSignatory(
          const model::AddSignatory &add_signatory) {
        protocol::AddSignatory pb_add_signatory;
        pb_add_signatory.set_account_id(add_signatory.account_id);
        pb_add_signatory.set_public_key(add_signatory.pubkey.to_hexstring());
        return pb_add_signatory;
      }

      model::AddSignatory PbCommandFactory::deserializeAddSignatory(
          const protocol::AddSignatory &pb_add_signatory) {
        model::AddSignatory add_signatory;
        add_signatory.account_id = pb_add_signatory.account_id();
        trySetHexKey(add_signatory.pubkey, pb_add_signatory.public_key());
        return add_signatory;
      }

      // create asset
      protocol::CreateAsset PbCommandFactory::serializeCreateAsset(
          const model::CreateAsset &create_asset) {
        protocol::CreateAsset pb_create_asset;
        pb_create_asset.set_asset_name(create_asset.asset_name);
        pb_create_asset.set_domain_id(create_asset.domain_id);
        pb_create_asset.set_precision(create_asset.precision);
        return pb_create_asset;
      }

      model::CreateAsset PbCommandFactory::deserializeCreateAsset(
          const protocol::CreateAsset &pb_create_asset) {
        model::CreateAsset create_asset;
        create_asset.asset_name = pb_create_asset.asset_name();
        create_asset.domain_id = pb_create_asset.domain_id();
        create_asset.precision =
            static_cast<uint8_t>(pb_create_asset.precision());
        return create_asset;
      }

      // create account
      protocol::CreateAccount PbCommandFactory::serializeCreateAccount(
          const model::CreateAccount &create_account) {
        protocol::CreateAccount pb_create_account;
        pb_create_account.set_account_name(create_account.account_name);
        pb_create_account.set_domain_id(create_account.domain_id);
        pb_create_account.set_public_key(create_account.pubkey.to_hexstring());
        return pb_create_account;
      }
      model::CreateAccount PbCommandFactory::deserializeCreateAccount(
          const protocol::CreateAccount &pb_create_account) {
        model::CreateAccount create_account;
        create_account.account_name = pb_create_account.account_name();
        create_account.domain_id = pb_create_account.domain_id();
        trySetHexKey(create_account.pubkey, pb_create_account.public_key());
        return create_account;
      }

      // create domain
      protocol::CreateDomain PbCommandFactory::serializeCreateDomain(
          const model::CreateDomain &create_domain) {
        protocol::CreateDomain pb_create_domain;
        pb_create_domain.set_domain_id(create_domain.domain_id);
        pb_create_domain.set_default_role(create_domain.user_default_role);
        return pb_create_domain;
      }

      model::CreateDomain PbCommandFactory::deserializeCreateDomain(
          const protocol::CreateDomain &pb_create_domain) {
        model::CreateDomain create_domain;
        create_domain.domain_id = pb_create_domain.domain_id();
        create_domain.user_default_role = pb_create_domain.default_role();
        return create_domain;
      }

      // remove signatory
      protocol::RemoveSignatory PbCommandFactory::serializeRemoveSignatory(
          const model::RemoveSignatory &remove_signatory) {
        protocol::RemoveSignatory pb_remove_signatory;
        pb_remove_signatory.set_account_id(remove_signatory.account_id);
        pb_remove_signatory.set_public_key(
            remove_signatory.pubkey.to_hexstring());
        return pb_remove_signatory;
      }

      model::RemoveSignatory PbCommandFactory::deserializeRemoveSignatory(
          const protocol::RemoveSignatory &pb_remove_signatory) {
        model::RemoveSignatory remove_signatory;
        remove_signatory.account_id = pb_remove_signatory.account_id();
        trySetHexKey(remove_signatory.pubkey, pb_remove_signatory.public_key());
        return remove_signatory;
      }
      // set account quorum
      protocol::SetAccountQuorum PbCommandFactory::serializeSetQuorum(
          const model::SetQuorum &set_account_quorum) {
        protocol::SetAccountQuorum pb_set_account_quorum;
        pb_set_account_quorum.set_account_id(set_account_quorum.account_id);
        pb_set_account_quorum.set_quorum(set_account_quorum.new_quorum);
        return pb_set_account_quorum;
      }
      model::SetQuorum PbCommandFactory::deserializeSetQuorum(
          const protocol::SetAccountQuorum &pb_set_account_quorum) {
        model::SetQuorum set_quorum;
        set_quorum.account_id = pb_set_account_quorum.account_id();
        set_quorum.new_quorum = pb_set_account_quorum.quorum();
        return set_quorum;
      }

      // transfer asset
      protocol::TransferAsset PbCommandFactory::serializeTransferAsset(
          const model::TransferAsset &transfer_asset) {
        protocol::TransferAsset pb_transfer_asset;

        pb_transfer_asset.set_src_account_id(transfer_asset.src_account_id);
        pb_transfer_asset.set_dest_account_id(transfer_asset.dest_account_id);
        pb_transfer_asset.set_asset_id(transfer_asset.asset_id);
        pb_transfer_asset.set_description(transfer_asset.description);
        pb_transfer_asset.set_amount(transfer_asset.amount);
        return pb_transfer_asset;
      }

      model::TransferAsset PbCommandFactory::deserializeTransferAsset(
          const protocol::TransferAsset &pb_subtract_asset_quantity) {
        model::TransferAsset transfer_asset;
        transfer_asset.src_account_id =
            pb_subtract_asset_quantity.src_account_id();
        transfer_asset.dest_account_id =
            pb_subtract_asset_quantity.dest_account_id();
        transfer_asset.asset_id = pb_subtract_asset_quantity.asset_id();
        transfer_asset.description = pb_subtract_asset_quantity.description();
        transfer_asset.amount = pb_subtract_asset_quantity.amount();
        return transfer_asset;
      }

      // Append Role
      model::AppendRole PbCommandFactory::deserializeAppendRole(
          const protocol::AppendRole &command) {
        return AppendRole(command.account_id(), command.role_name());
      }

      protocol::AppendRole PbCommandFactory::serializeAppendRole(
          const model::AppendRole &command) {
        protocol::AppendRole cmd;
        cmd.set_account_id(command.account_id);
        cmd.set_role_name(command.role_name);
        return cmd;
      }

      // Append Role
      model::DetachRole PbCommandFactory::deserializeDetachRole(
          const protocol::DetachRole &command) {
        return DetachRole(command.account_id(), command.role_name());
      }

      protocol::DetachRole PbCommandFactory::serializeDetachRole(
          const model::DetachRole &command) {
        protocol::DetachRole cmd;
        cmd.set_account_id(command.account_id);
        cmd.set_role_name(command.role_name);
        return cmd;
      }

      // Create Role
      model::CreateRole PbCommandFactory::deserializeCreateRole(
          const protocol::CreateRole &command) {
        std::set<std::string> perms;

        std::for_each(command.permissions().begin(),
                      command.permissions().end(),
                      [&perms, this](auto perm) {
                        auto it = this->pb_role_map_.left.find(
                            static_cast<protocol::RolePermission>(perm));
                        if (it != this->pb_role_map_.left.end()) {
                          perms.insert(it->second);
                        }
                      });
        return CreateRole(command.role_name(), perms);
      }

      protocol::CreateRole PbCommandFactory::serializeCreateRole(
          const model::CreateRole &command) {
        protocol::CreateRole cmd;
        cmd.set_role_name(command.role_name);
        std::for_each(command.permissions.begin(),
                      command.permissions.end(),
                      [&cmd, this](auto perm) {
                        auto perm_name = this->pb_role_map_.right.at(perm);
                        cmd.add_permissions(perm_name);
                      });
        return cmd;
      }

      // Grant Permission
      protocol::GrantPermission PbCommandFactory::serializeGrantPermission(
          const model::GrantPermission &command) {
        protocol::GrantPermission cmd;
        cmd.set_account_id(command.account_id);
        auto perm = pb_grant_map_.right.at(command.permission_name);
        cmd.set_permission(perm);
        return cmd;
      }

      model::GrantPermission PbCommandFactory::deserializeGrantPermission(
          const protocol::GrantPermission &command) {
        auto it = pb_grant_map_.left.find(command.permission());
        if (it == pb_grant_map_.left.end()) {
          return {};
        }
        return GrantPermission(command.account_id(), it->second);
      }

      protocol::RevokePermission PbCommandFactory::serializeRevokePermission(
          const model::RevokePermission &command) {
        protocol::RevokePermission cmd;
        cmd.set_account_id(command.account_id);
        auto permission = pb_grant_map_.right.at(command.permission_name);
        cmd.set_permission(permission);
        return cmd;
      }

      model::RevokePermission PbCommandFactory::deserializeRevokePermission(
          const protocol::RevokePermission &command) {
        auto it = pb_grant_map_.left.find(command.permission());
        if (it == pb_grant_map_.left.end()) {
          return {};
        }
        return RevokePermission(command.account_id(), it->second);
      }

      protocol::SetAccountDetail PbCommandFactory::serializeSetAccountDetail(
          const model::SetAccountDetail &command) {
        protocol::SetAccountDetail cmd;
        cmd.set_account_id(command.account_id);
        cmd.set_key(command.key);
        cmd.set_value(command.value);
        return cmd;
      }

      model::SetAccountDetail PbCommandFactory::deserializeSetAccountDetail(
          const protocol::SetAccountDetail &command) {
        model::SetAccountDetail setAccountDetail;
        setAccountDetail.account_id = command.account_id();
        setAccountDetail.key = command.key();
        setAccountDetail.value = command.value();
        return setAccountDetail;
      }

      protocol::Command PbCommandFactory::serializeAbstractCommand(
          const model::Command &command) {
        PbCommandFactory commandFactory;
        auto cmd = protocol::Command();
        // TODO 26/09/17 grimadas: refactor this #VARIANT

        // -----|CreateRole|-----
        if (instanceof <model::CreateRole>(command)) {
          auto serialized = commandFactory.serializeCreateRole(
              static_cast<const model::CreateRole &>(command));
          cmd.set_allocated_create_role(new protocol::CreateRole(serialized));
        }

        // -----|AppendRole|-----
        if (instanceof <model::AppendRole>(command)) {
          auto serialized = commandFactory.serializeAppendRole(
              static_cast<const model::AppendRole &>(command));
          cmd.set_allocated_append_role(new protocol::AppendRole(serialized));
        }

        // -----|DetachRole|-----
        if (instanceof <model::DetachRole>(command)) {
          auto serialized = commandFactory.serializeDetachRole(
              static_cast<const model::DetachRole &>(command));
          cmd.set_allocated_detach_role(new protocol::DetachRole(serialized));
        }

        // -----|GrantPermission|-----
        if (instanceof <model::GrantPermission>(command)) {
          auto serialized = commandFactory.serializeGrantPermission(
              static_cast<const model::GrantPermission &>(command));
          cmd.set_allocated_grant_permission(
              new protocol::GrantPermission(serialized));
        }

        // -----|RevokePermission|-----
        if (instanceof <model::RevokePermission>(command)) {
          auto serialized = commandFactory.serializeRevokePermission(
              static_cast<const model::RevokePermission &>(command));
          cmd.set_allocated_revoke_permission(
              new protocol::RevokePermission(serialized));
        }

        // -----|AddAssetQuantity|-----
        if (instanceof <model::AddAssetQuantity>(command)) {
          auto serialized = commandFactory.serializeAddAssetQuantity(
              static_cast<const model::AddAssetQuantity &>(command));
          cmd.set_allocated_add_asset_quantity(
              new protocol::AddAssetQuantity(serialized));
        }

        // -----|SubtractAssetQuantity|-----
        if (instanceof <model::SubtractAssetQuantity>(command)) {
          auto serialized = commandFactory.serializeSubtractAssetQuantity(
              static_cast<const model::SubtractAssetQuantity &>(command));
          cmd.set_allocated_subtract_asset_quantity(
              new protocol::SubtractAssetQuantity(serialized));
        }

        // -----|AddPeer|-----
        if (instanceof <model::AddPeer>(command)) {
          auto serialized = commandFactory.serializeAddPeer(
              static_cast<const model::AddPeer &>(command));
          cmd.set_allocated_add_peer(new protocol::AddPeer(serialized));
        }

        // -----|AddSignatory|-----
        if (instanceof <model::AddSignatory>(command)) {
          auto serialized = commandFactory.serializeAddSignatory(
              static_cast<const model::AddSignatory &>(command));
          cmd.set_allocated_add_signatory(
              new protocol::AddSignatory(serialized));
        }

        // -----|CreateAsset|-----
        if (instanceof <model::CreateAsset>(command)) {
          auto serialized = commandFactory.serializeCreateAsset(
              static_cast<const model::CreateAsset &>(command));
          cmd.set_allocated_create_asset(new protocol::CreateAsset(serialized));
        }

        // -----|CreateAccount|-----
        if (instanceof <model::CreateAccount>(command)) {
          auto serialized = commandFactory.serializeCreateAccount(
              static_cast<const model::CreateAccount &>(command));
          cmd.set_allocated_create_account(
              new protocol::CreateAccount(serialized));
        }

        // -----|SetAccountDetail|-----
        if (instanceof <model::SetAccountDetail>(command)) {
          auto serialized = commandFactory.serializeSetAccountDetail(
              static_cast<const model::SetAccountDetail &>(command));
          cmd.set_allocated_set_account_detail(
              new protocol::SetAccountDetail(serialized));
        }

        // -----|CreateDomain|-----
        if (instanceof <model::CreateDomain>(command)) {
          auto serialized = commandFactory.serializeCreateDomain(
              static_cast<const model::CreateDomain &>(command));
          cmd.set_allocated_create_domain(
              new protocol::CreateDomain(serialized));
        }

        // -----|RemoveSignatory|-----
        if (instanceof <model::RemoveSignatory>(command)) {
          auto serialized = commandFactory.serializeRemoveSignatory(
              static_cast<const model::RemoveSignatory &>(command));
          cmd.set_allocated_remove_signatory(
              new protocol::RemoveSignatory(serialized));
        }

        // -----|SetAccountQuorum|-----
        if (instanceof <model::SetQuorum>(command)) {
          auto serialized = commandFactory.serializeSetQuorum(
              static_cast<const model::SetQuorum &>(command));
          cmd.set_allocated_set_account_quorum(
              new protocol::SetAccountQuorum(serialized));
        }

        // -----|TransferAsset|-----
        if (instanceof <model::TransferAsset>(command)) {
          auto serialized = commandFactory.serializeTransferAsset(
              static_cast<const model::TransferAsset &>(command));
          cmd.set_allocated_transfer_asset(
              new protocol::TransferAsset(serialized));
        }

        return cmd;
      }

      std::shared_ptr<model::Command>
      PbCommandFactory::deserializeAbstractCommand(
          const protocol::Command &command) {
        PbCommandFactory commandFactory;
        std::shared_ptr<model::Command> val;

        // -----|CreateRole|-----
        if (command.has_create_role()) {
          auto pb_command = command.create_role();
          auto cmd = commandFactory.deserializeCreateRole(pb_command);
          val = std::make_shared<model::CreateRole>(cmd);
        }

        // -----|AppendRole|-----
        if (command.has_append_role()) {
          auto pb_command = command.append_role();
          auto cmd = commandFactory.deserializeAppendRole(pb_command);
          val = std::make_shared<model::AppendRole>(cmd);
        }

        // -----|DetachRole|-----
        if (command.has_detach_role()) {
          auto pb_command = command.detach_role();
          auto cmd = commandFactory.deserializeDetachRole(pb_command);
          val = std::make_shared<model::DetachRole>(cmd);
        }

        // -----|GrantPermission|-----
        if (command.has_grant_permission()) {
          auto pb_command = command.grant_permission();
          auto cmd = commandFactory.deserializeGrantPermission(pb_command);
          val = std::make_shared<model::GrantPermission>(cmd);
        }

        // -----|RevokePermission|-----
        if (command.has_revoke_permission()) {
          auto pb_command = command.revoke_permission();
          auto cmd = commandFactory.deserializeRevokePermission(pb_command);
          val = std::make_shared<model::RevokePermission>(cmd);
        }

        // -----|AddAssetQuantity|-----
        if (command.has_add_asset_quantity()) {
          auto pb_command = command.add_asset_quantity();
          auto cmd = commandFactory.deserializeAddAssetQuantity(pb_command);
          val = std::make_shared<model::AddAssetQuantity>(cmd);
        }

        // -----|SubtractAssetQuantity|-----
        if (command.has_subtract_asset_quantity()) {
          auto pb_command = command.subtract_asset_quantity();
          auto cmd =
              commandFactory.deserializeSubtractAssetQuantity(pb_command);
          val = std::make_shared<model::SubtractAssetQuantity>(cmd);
        }

        // -----|AddPeer|-----
        if (command.has_add_peer()) {
          auto pb_command = command.add_peer();
          auto cmd = commandFactory.deserializeAddPeer(pb_command);
          val = std::make_shared<model::AddPeer>(cmd);
        }

        // -----|AddSignatory|-----
        if (command.has_add_signatory()) {
          auto pb_command = command.add_signatory();
          auto cmd = commandFactory.deserializeAddSignatory(pb_command);
          val = std::make_shared<model::AddSignatory>(cmd);
        }

        // -----|CreateAsset|-----
        if (command.has_create_asset()) {
          auto pb_command = command.create_asset();
          auto cmd = commandFactory.deserializeCreateAsset(pb_command);
          val = std::make_shared<model::CreateAsset>(cmd);
        }

        // -----|CreateAccount|-----
        if (command.has_create_account()) {
          auto pb_command = command.create_account();
          auto cmd = commandFactory.deserializeCreateAccount(pb_command);
          val = std::make_shared<model::CreateAccount>(cmd);
        }

        // -----|SetAccountDetail|-----
        if (command.has_set_account_detail()) {
          auto pb_command = command.set_account_detail();
          auto cmd = commandFactory.deserializeSetAccountDetail(pb_command);
          val = std::make_shared<model::SetAccountDetail>(cmd);
        }

        // -----|CreateDomain|-----
        if (command.has_create_domain()) {
          auto pb_command = command.create_domain();
          auto cmd = commandFactory.deserializeCreateDomain(pb_command);
          val = std::make_shared<model::CreateDomain>(cmd);
        }

        // -----|RemoveSignatory|-----
        if (command.has_remove_signatory()) {
          auto pb_command = command.remove_signatory();
          auto cmd = commandFactory.deserializeRemoveSignatory(pb_command);
          val = std::make_shared<model::RemoveSignatory>(cmd);
        }

        // -----|SetAccountQuorum|-----
        if (command.has_set_account_quorum()) {
          auto pb_command = command.set_account_quorum();
          auto cmd = commandFactory.deserializeSetQuorum(pb_command);
          val = std::make_shared<model::SetQuorum>(cmd);
        }

        // -----|TransferAsset|-----
        if (command.has_transfer_asset()) {
          auto pb_command = command.transfer_asset();
          auto cmd = commandFactory.deserializeTransferAsset(pb_command);
          val = std::make_shared<model::TransferAsset>(cmd);
        }

        return val;
      }

    }  // namespace converters
  }    // namespace model
}  // namespace iroha
