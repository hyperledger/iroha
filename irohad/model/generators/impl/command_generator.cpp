/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/generators/command_generator.hpp"
#include "model/commands/add_asset_quantity.hpp"
#include "model/commands/add_peer.hpp"
#include "model/commands/add_signatory.hpp"
#include "model/commands/append_role.hpp"
#include "model/commands/create_account.hpp"
#include "model/commands/create_asset.hpp"
#include "model/commands/create_domain.hpp"
#include "model/commands/create_role.hpp"
#include "model/commands/remove_signatory.hpp"
#include "model/commands/set_account_detail.hpp"
#include "model/commands/set_quorum.hpp"
#include "model/commands/subtract_asset_quantity.hpp"
#include "model/commands/transfer_asset.hpp"
#include "model/permissions.hpp"

using namespace generator;
using namespace shared_model::permissions;

namespace iroha {
  namespace model {
    namespace generators {

      std::shared_ptr<Command> CommandGenerator::generateAddPeer(
          const Peer &peer) {
        return generateCommand<AddPeer>(peer);
      }

      std::shared_ptr<Command> CommandGenerator::generateAddSignatory(
          const std::string &account_id, const pubkey_t &key) {
        return generateCommand<AddSignatory>(account_id, key);
      }

      std::shared_ptr<Command> CommandGenerator::generateRemoveSignatory(
          const std::string &account_id, const pubkey_t &key) {
        return generateCommand<RemoveSignatory>(account_id, key);
      }

      std::shared_ptr<Command> CommandGenerator::generateCreateAccount(
          const std::string &account_name,
          const std::string &domain_id,
          const pubkey_t &key) {
        return generateCommand<CreateAccount>(account_name, domain_id, key);
      }

      std::shared_ptr<Command> CommandGenerator::generateCreateDomain(
          const std::string &domain_id, const std::string &default_role) {
        return generateCommand<CreateDomain>(domain_id, default_role);
      }

      std::shared_ptr<Command> CommandGenerator::generateCreateAsset(
          const std::string &asset_name,
          const std::string &domain_id,
          uint8_t precision) {
        return generateCommand<CreateAsset>(asset_name, domain_id, precision);
      }

      std::shared_ptr<Command> CommandGenerator::generateCreateAdminRole(
          std::string role_name) {
        std::set<std::string> perms = {
            can_create_domain, can_create_account, can_add_peer};
        perms.insert(edit_self_group.begin(), edit_self_group.end());
        perms.insert(read_all_group.begin(), read_all_group.end());
        return std::make_shared<CreateRole>(role_name, perms);
      }

      std::shared_ptr<Command> CommandGenerator::generateCreateUserRole(
          std::string role_name) {
        std::set<std::string> perms = {can_receive, can_transfer};
        // User can read their account
        perms.insert(read_self_group.begin(), read_self_group.end());
        // User can grant permissions to others
        perms.insert(grant_group.begin(), grant_group.end());
        perms.insert(edit_self_group.begin(), edit_self_group.end());
        return std::make_shared<CreateRole>(role_name, perms);
      }

      std::shared_ptr<Command> CommandGenerator::generateCreateAssetCreatorRole(
          std::string role_name) {
        std::set<std::string> perms = {can_receive, can_transfer};
        perms.insert(asset_creator_group.begin(), asset_creator_group.end());
        perms.insert(read_self_group.begin(), read_self_group.begin());
        return std::make_shared<CreateRole>(role_name, perms);
      }

      std::shared_ptr<Command> CommandGenerator::generateAddAssetQuantity(
          const std::string &asset_id, const std::string &amount, const std::string &description) {
        return generateCommand<AddAssetQuantity>(asset_id, amount, description);
      }

      std::shared_ptr<Command> CommandGenerator::generateSubtractAssetQuantity(
          const std::string &asset_id, const std::string &amount, const std::string &description) {
        return generateCommand<SubtractAssetQuantity>(asset_id, amount, description);
      }

      std::shared_ptr<Command> CommandGenerator::generateSetQuorum(
          const std::string &account_id, uint32_t quorum) {
        return generateCommand<SetQuorum>(account_id, quorum);
      }

      std::shared_ptr<Command> CommandGenerator::generateTransferAsset(
          const std::string &src_account,
          const std::string &dest_account,
          const std::string &asset_id,
          const std::string &amount) {
        return generateCommand<TransferAsset>(
            src_account, dest_account, asset_id, amount);
      }

      std::shared_ptr<Command> CommandGenerator::generateAppendRole(
          const std::string &account_id, const std::string &role_name) {
        return generateCommand<AppendRole>(account_id, role_name);
      }

    }  // namespace generators
  }    // namespace model
}  // namespace iroha
