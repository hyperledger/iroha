/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ametsuchi/impl/rocksdb_command_executor.hpp"

#include <fmt/core.h>
#include <rocksdb/utilities/transaction.h>
#include <boost/algorithm/string.hpp>
#include <boost/variant/apply_visitor.hpp>
#include "ametsuchi/impl/executor_common.hpp"
#include "ametsuchi/setting_query.hpp"
#include "ametsuchi/vm_caller.hpp"
#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/call_engine.hpp"
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

using namespace iroha;
using namespace iroha::ametsuchi;

using shared_model::interface::permissions::Grantable;
using shared_model::interface::permissions::Role;

using shared_model::interface::GrantablePermissionSet;
using shared_model::interface::RolePermissionSet;

RocksDbCommandExecutor::RocksDbCommandExecutor(
    std::shared_ptr<RocksDBPort> db_port,
    std::shared_ptr<shared_model::interface::PermissionToString> perm_converter,
    std::optional<std::reference_wrapper<const VmCaller>> vm_caller)
    : db_port_(std::move(db_port)),
      perm_converter_{std::move(perm_converter)},
      vm_caller_{std::move(vm_caller)} {
  db_port_->prepareTransaction(*db_context_);
}

RocksDbCommandExecutor::~RocksDbCommandExecutor() = default;

CommandResult RocksDbCommandExecutor::execute(
    const shared_model::interface::Command &cmd,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation) {
  return boost::apply_visitor(
      [this, &creator_account_id, &tx_hash, cmd_index, do_validation](
          const auto &command) -> CommandResult {
        try {
          RocksDbCommon common(db_context_);

          RolePermissionSet creator_permissions;
          if (do_validation) {
            auto names = splitId(creator_account_id);
            auto &account_name = names.at(0);
            auto &domain_id = names.at(1);

            // get account permissions
            creator_permissions =
                accountPermissions(common, domain_id, account_name);
          }

          return (*this)(command,
                         creator_account_id,
                         tx_hash,
                         cmd_index,
                         do_validation,
                         creator_permissions);
        } catch (IrohaDbError &e) {
          return expected::makeError(
              CommandError{command.toString(), e.code(), e.what()});
        }
      },
      cmd.get());
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AddAssetQuantity &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);
  rocksdb::Status status;

  // TODO(iceseer): fix the case there will be no delimiter
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.assetId());
  auto &asset_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &amount = command.amount();

  if (do_validation)
    checkPermissions(domain_id,
                     creator_domain_id,
                     creator_permissions,
                     Role::kAddAssetQty,
                     Role::kAddDomainAssetQty);

  // check if asset exists and construct amount by precision
  shared_model::interface::Amount result(
      forAsset(common,
               domain_id,
               asset_name,
               [](auto /*asset*/, auto /*domain*/, auto opt_precision) {
                 assert(opt_precision);
                 return *opt_precision;
               }));

  uint64_t account_asset_size(forAccountAssetSize(
      common,
      creator_domain_id,
      creator_account_name,
      [](auto /*account*/, auto /*domain*/, auto opt_account_asset_size) {
        if (opt_account_asset_size)
          return *opt_account_asset_size;
        return uint64_t(0ull);
      }));

  {  // get account asset balance
    auto opt_account_assets(forAccountAssets(
        common,
        creator_domain_id,
        creator_account_name,
        command.assetId(),
        [](auto /*account*/, auto /*domain*/, auto /*asset*/, auto opt_amount) {
          return opt_amount;
        }));
    if (!opt_account_assets)
      ++account_asset_size;
    else
      result = std::move(*opt_account_assets);
  }

  result += amount;
  common.valueBuffer().assign(result.toStringRepr());
  if (db_context_->value_buffer[0] == 'N')
    throw IrohaDbError(
        9, fmt::format("Invalid asset amount {}", result.toString()));

  forAccountAssets<kDbOperation::kPut>(common,
                                       creator_domain_id,
                                       creator_account_name,
                                       command.assetId(),
                                       [](auto /*account*/,
                                          auto /*domain*/,
                                          auto /*asset*/,
                                          auto /*opt_amount*/) {});

  common.encode(account_asset_size);
  forAccountAssetSize<kDbOperation::kPut>(
      common,
      creator_domain_id,
      creator_account_name,
      [](auto /*account*/, auto /*domain*/, auto /*opt_account_asset_size*/) {
      });

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AddPeer &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto const peer = command.peer();
  if (!peer)
    throw IrohaDbError(10, fmt::format("No peer"));

  rocksdb::Status status;
  RocksDbCommon common(db_context_);

  if (do_validation)
    checkPermissions(creator_permissions, Role::kAddPeer);

  status = common.get(fmtstrings::kPeerAddress, peer->pubkey());
  mustNotExist(status,
               [&] { return fmt::format("Pubkey {}", peer->pubkey()); });

  /// Store address
  db_context_->value_buffer.assign(peer->address());
  status = common.put(fmtstrings::kPeerAddress, peer->pubkey());
  mustExist(status, [&] { return fmt::format("Pubkey {}", peer->pubkey()); });

  /// Store TLS if present
  if (peer->tlsCertificate().has_value()) {
    db_context_->value_buffer.assign(peer->tlsCertificate().value());
    status = common.put(fmtstrings::kPeerTLS, peer->pubkey());
    mustExist(status,
              [&] { return fmt::format("TLS for pubkey {}", peer->pubkey()); });
  }

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AddSignatory &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  RocksDbCommon common(db_context_);
  if (do_validation) {
    GrantablePermissionSet granted_account_permissions;
    if (auto opt_permissions = forGrantablePermissions(
            common,
            creator_domain_id,
            creator_account_name,
            domain_id,
            account_name,
            [](auto /*account*/,
               auto /*domain*/,
               auto /*grantee_account*/,
               auto /*grantee_domain*/,
               auto opt_permissions) { return opt_permissions; })) {
      granted_account_permissions = std::move(*opt_permissions);
    }

    checkPermissions(creator_permissions,
                     granted_account_permissions,
                     Role::kAddSignatory,
                     Grantable::kAddMySignatory);
  }

  forSignatory<kDbOperation::kGet, kDbEntry::kMustNotExist>(
      common, domain_id, account_name, command.pubkey(), [](auto, auto, auto) {
      });

  forSignatory<kDbOperation::kPut>(
      common, domain_id, account_name, command.pubkey(), [](auto, auto, auto) {
      });

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AppendRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &role_name = command.roleName();

  if (do_validation)
    checkPermissions(creator_permissions, Role::kAppendRole);

  // check if account already has role
  forAccountRole<kDbOperation::kGet, kDbEntry::kMustNotExist>(
      common, domain_id, account_name, role_name, [](auto, auto, auto) {});

  forRole<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, role_name, [&](auto role, auto opt_permissions) {
        assert(opt_permissions);
        if (!opt_permissions->isSubsetOf(creator_permissions))
          throw IrohaDbError(16, fmt::format("Not enough permissions."));
      });

  common.valueBuffer() = "";
  forAccountRole<kDbOperation::kPut>(
      common, domain_id, account_name, role_name, [](auto, auto, auto) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CallEngine &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(26, fmt::format("Not implemented."));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CompareAndSetAccountDetail &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(26, fmt::format("Not implemented."));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateAccount &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto &account_name = command.accountName();
  auto &domain_id = command.domainId();
  auto pubkey = command.pubkey();
  boost::algorithm::to_lower(pubkey);

  if (do_validation)
    checkPermissions(creator_permissions, Role::kCreateAccount);

  // check if domain exists
  std::string default_role(forDomain<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, domain_id, [](auto, auto opt_default_role) {
        assert(opt_default_role);
        return *opt_default_role;
      }));

  forRole<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, default_role, [&](auto /*role*/, auto opt_permissions) {
        assert(opt_permissions);
        if (!opt_permissions->isSubsetOf(creator_permissions))
          throw IrohaDbError(17, fmt::format("Not enough permissions."));
      });

  common.valueBuffer() = "";
  forAccountRole<kDbOperation::kPut>(
      common,
      domain_id,
      account_name,
      default_role,
      [](auto /*account*/, auto /*domain*/, auto /*role*/) {});

  // check if account already exists
  if (do_validation)
    forAccount<kDbOperation::kGet, kDbEntry::kMustNotExist>(
        common, domain_id, account_name, [](auto /*account*/, auto /*domain*/) {
        });

  common.valueBuffer() = "";
  forSignatory<kDbOperation::kPut>(
      common,
      domain_id,
      account_name,
      pubkey,
      [](auto /*account*/, auto /*domain*/, auto /*pubkey*/) {});

  common.encode(1);
  forQuorum<kDbOperation::kPut>(
      common,
      domain_id,
      account_name,
      [](auto /*account*/, auto /*domain*/, auto /*opt_quorum*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateAsset &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto &domain_id = command.domainId();
  auto &asset_name = command.assetName();

  if (do_validation) {
    checkPermissions(creator_permissions, Role::kCreateAsset);

    // check if asset already exists
    forAsset<kDbOperation::kGet, kDbEntry::kMustNotExist>(
        common,
        domain_id,
        asset_name,
        [](auto /*asset*/, auto /*domain*/, auto /*precision*/) {});

    // check if domain exists
    forDomain<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, domain_id, [](auto /*domain*/, auto /*opt_default_role*/) {});
  }

  common.encode(command.precision());
  forAsset<kDbOperation::kPut>(
      common,
      domain_id,
      asset_name,
      [](auto /*asset*/, auto /*domain*/, auto /*opt_precision*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateDomain &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto &domain_id = command.domainId();
  auto &default_role = command.userDefaultRole();

  if (do_validation) {
    // no privilege escalation check here
    checkPermissions(creator_permissions, Role::kCreateDomain);

    // check if domain already exists
    forDomain<kDbOperation::kGet, kDbEntry::kMustNotExist>(
        common, domain_id, [](auto /*domain*/, auto /*opt_default_role*/) {});

    // check if role exists
    forRole<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, default_role, [&](auto /*role*/, auto /*opt_permissions*/) {});
  }

  common.valueBuffer().assign(default_role);
  forDomain<kDbOperation::kPut>(
      common, domain_id, [](auto /*domain*/, auto /*opt_default_role*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto &role_name = command.roleName();
  auto role_permissions = command.rolePermissions();
  if (role_permissions.isSet(Role::kRoot)) {
    role_permissions.setAll();
  }

  if (do_validation) {
    checkPermissions(creator_permissions, Role::kCreateRole);
    if (!role_permissions.isSubsetOf(creator_permissions))
      throw IrohaDbError(18, fmt::format("Not enough permissions."));

    // check if role already exists
    forRole<kDbOperation::kGet, kDbEntry::kMustNotExist>(
        common, role_name, [&](auto /*role*/, auto /*opt_permissions*/) {});
  }

  common.valueBuffer().assign(role_permissions.toBitstring());
  forRole<kDbOperation::kPut>(
      common, role_name, [&](auto /*role*/, auto /*opt_permissions*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::DetachRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &role_name = command.roleName();

  if (do_validation)
    checkPermissions(creator_permissions, Role::kDetachRole);

  forRole<kDbOperation::kGet, kDbEntry::kMustExist>(
      common, role_name, [&](auto /*role*/, auto /*opt_permissions*/) {});

  if (do_validation)
    forAccountRole<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, domain_id, account_name, role_name, [](auto, auto, auto) {});

  forAccountRole<kDbOperation::kDel>(
      common, domain_id, account_name, role_name, [](auto, auto, auto) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::GrantPermission &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto grantee_names = splitId(creator_account_id);
  auto &grantee_account_name = grantee_names.at(0);
  auto &grantee_domain_id = grantee_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  auto granted_perm = command.permissionName();
  auto required_perm =
      shared_model::interface::permissions::permissionFor(granted_perm);

  if (do_validation) {
    checkPermissions(creator_permissions, required_perm);

    // check if account exists
    forAccount<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, domain_id, account_name, [](auto /*account*/, auto /*domain*/) {
        });
  }

  GrantablePermissionSet granted_account_permissions;
  if (auto opt_permissions = forGrantablePermissions(
          common,
          domain_id,
          account_name,
          grantee_domain_id,
          grantee_account_name,
          [](auto /*account*/,
             auto /*domain*/,
             auto /*grantee_account*/,
             auto /*grantee_domain*/,
             auto opt_permissions) { return opt_permissions; })) {
    granted_account_permissions = std::move(*opt_permissions);
  }

  // check if already granted
  if (granted_account_permissions.isSet(granted_perm))
    throw IrohaDbError(19, fmt::format("Permission is set"));

  granted_account_permissions.set(granted_perm);
  common.valueBuffer().assign(granted_account_permissions.toBitstring());
  forGrantablePermissions<kDbOperation::kPut, kDbEntry::kAll>(
      common,
      domain_id,
      account_name,
      grantee_domain_id,
      grantee_account_name,
      [](auto /*account*/,
         auto /*domain*/,
         auto /*grantee_account*/,
         auto /*grantee_domain*/,
         auto /*opt_permissions*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RemovePeer &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  if (command.pubkey().empty())
    throw IrohaDbError(20, fmt::format("Pubkey empty"));

  RocksDbCommon common(db_context_);
  if (do_validation) {
    checkPermissions(creator_permissions, Role::kRemovePeer);

    forPeerAddress<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, command.pubkey(), [](auto /*pubkey*/, auto /*opt_address*/) {});
  }

  forPeerAddress<kDbOperation::kDel>(
      common, command.pubkey(), [](auto /*pubkey*/, auto /*opt_address*/) {});

  forPeerTLS<kDbOperation::kDel>(
      common, command.pubkey(), [](auto /*pubkey*/, auto /*opt_tls*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RemoveSignatory &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  RocksDbCommon common(db_context_);
  if (do_validation) {
    GrantablePermissionSet granted_account_permissions;
    if (auto opt_permissions = forGrantablePermissions(
            common,
            creator_domain_id,
            creator_account_name,
            domain_id,
            account_name,
            [](auto /*account*/,
               auto /*domain*/,
               auto /*grantee_account*/,
               auto /*grantee_domain*/,
               auto opt_permissions) { return opt_permissions; })) {
      granted_account_permissions = std::move(*opt_permissions);
    }

    checkPermissions(creator_permissions,
                     granted_account_permissions,
                     Role::kRemoveSignatory,
                     Grantable::kRemoveMySignatory);

    forSignatory<kDbOperation::kGet, kDbEntry::kMustExist>(
        common,
        domain_id,
        account_name,
        command.pubkey(),
        [](auto, auto, auto) {});
  }

  forSignatory<kDbOperation::kDel>(
      common, domain_id, account_name, command.pubkey(), [](auto, auto, auto) {
      });

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RevokePermission &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto grantee_names = splitId(creator_account_id);
  auto &grantee_account_name = grantee_names.at(0);
  auto &grantee_domain_id = grantee_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  auto const revoked_perm = command.permissionName();
  auto required_perm =
      shared_model::interface::permissions::permissionFor(revoked_perm);

  if (do_validation) {
    checkPermissions(creator_permissions, required_perm);

    // check if account exists
    forAccount<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, domain_id, account_name, [](auto /*account*/, auto /*domain*/) {
        });
  }

  GrantablePermissionSet granted_account_permissions;
  if (auto opt_permissions = forGrantablePermissions(
          common,
          domain_id,
          account_name,
          grantee_domain_id,
          grantee_account_name,
          [](auto /*account*/,
             auto /*domain*/,
             auto /*grantee_account*/,
             auto /*grantee_domain*/,
             auto opt_permissions) { return opt_permissions; })) {
    granted_account_permissions = std::move(*opt_permissions);
  }

  // check if not granted
  if (!granted_account_permissions.isSet(revoked_perm))
    throw IrohaDbError(20, fmt::format("Permission not set"));

  granted_account_permissions.unset(revoked_perm);
  common.valueBuffer().assign(granted_account_permissions.toBitstring());
  forGrantablePermissions<kDbOperation::kPut, kDbEntry::kAll>(
      common,
      domain_id,
      account_name,
      grantee_domain_id,
      grantee_account_name,
      [](auto /*account*/,
         auto /*domain*/,
         auto /*grantee_account*/,
         auto /*grantee_domain*/,
         auto /*opt_permissions*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetAccountDetail &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  if (do_validation) {
    if (command.accountId() != creator_account_id) {
      GrantablePermissionSet granted_account_permissions;
      if (auto opt_permissions = forGrantablePermissions(
              common,
              creator_domain_id,
              creator_account_name,
              domain_id,
              account_name,
              [](auto /*account*/,
                 auto /*domain*/,
                 auto /*grantee_account*/,
                 auto /*grantee_domain*/,
                 auto opt_permissions) { return opt_permissions; })) {
        granted_account_permissions = std::move(*opt_permissions);
      }

      checkPermissions(creator_permissions,
                       granted_account_permissions,
                       Role::kSetDetail,
                       Grantable::kSetMyAccountDetail);
    }

    // check if account exists
    forAccount<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, domain_id, account_name, [](auto /*account*/, auto /*domain*/) {
        });
  }

  common.valueBuffer().assign(command.value());
  forAccountDetail<kDbOperation::kPut>(common,
                                       domain_id,
                                       account_name,
                                       creator_domain_id,
                                       creator_account_name,
                                       command.key(),
                                       [](auto /*account*/,
                                          auto /*domain*/,
                                          auto /*creator_account*/,
                                          auto /*creator_domain*/,
                                          auto /*key*/,
                                          auto /*opt_value*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetQuorum &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.accountId());
  auto &account_name = names.at(0);
  auto &domain_id = names.at(1);

  if (do_validation) {
    // have permissions
    checkPermissions(creator_permissions, Role::kSetQuorum);

    // check if account exists
    forAccount<kDbOperation::kGet, kDbEntry::kMustExist>(
        common, domain_id, account_name, [](auto /*account*/, auto /*domain*/) {
        });

    GrantablePermissionSet granted_account_permissions;
    if (auto opt_permissions = forGrantablePermissions(
            common,
            creator_domain_id,
            creator_account_name,
            domain_id,
            account_name,
            [](auto /*account*/,
               auto /*domain*/,
               auto /*grantee_account*/,
               auto /*grantee_domain*/,
               auto opt_permissions) { return opt_permissions; })) {
      granted_account_permissions = std::move(*opt_permissions);
    }

    checkPermissions(creator_permissions,
                     granted_account_permissions,
                     Role::kRoot,
                     Grantable::kSetMyQuorum);
  }

  common.encode(1);
  forQuorum<kDbOperation::kPut>(
      common,
      domain_id,
      account_name,
      [](auto /*account*/, auto /*domain*/, auto /*opt_quorum*/) {});

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SubtractAssetQuantity &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  // TODO(iceseer): fix the case there will be no delimiter
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto names = splitId(command.assetId());
  auto &asset_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &amount = command.amount();

  RocksDbCommon common(db_context_);
  if (do_validation)
    checkPermissions(domain_id,
                     creator_domain_id,
                     creator_permissions,
                     Role::kSubtractAssetQty,
                     Role::kSubtractDomainAssetQty);

  // check if asset exists
  shared_model::interface::Amount result(
      forAsset(common,
               domain_id,
               asset_name,
               [](auto /*asset*/, auto /*domain*/, auto opt_precision) {
                 assert(opt_precision);
                 return *opt_precision;
               }));

  if (auto opt_amount =
          forAccountAssets<kDbOperation::kGet, kDbEntry::kCanExist>(
              common,
              creator_domain_id,
              creator_account_name,
              command.assetId(),
              [](auto /*account*/,
                 auto /*domain*/,
                 auto /*asset*/,
                 auto opt_amount) { return opt_amount; })) {
    result = std::move(*opt_amount);
  }

  uint64_t account_asset_size(forAccountAssetSize(
      common,
      creator_domain_id,
      creator_account_name,
      [](auto /*account*/, auto /*domain*/, auto opt_account_asset_size) {
        if (opt_account_asset_size)
          return *opt_account_asset_size;
        return uint64_t(0ull);
      }));

  result -= amount;
  common.valueBuffer().assign(result.toStringRepr());
  if (db_context_->value_buffer[0] == 'N')
    throw IrohaDbError(21, fmt::format("Invalid result"));

  forAccountAssets<kDbOperation::kPut>(common,
                                       creator_domain_id,
                                       creator_account_name,
                                       command.assetId(),
                                       [](auto /*account*/,
                                          auto /*domain*/,
                                          auto /*asset*/,
                                          auto /*opt_amount*/) {});

  if (result == shared_model::interface::Amount("0")) {
    --account_asset_size;

    common.encode(account_asset_size);
    forAccountAssetSize<kDbOperation::kPut>(
        common,
        creator_domain_id,
        creator_account_name,
        [](auto /*account*/, auto /*domain*/, auto /*opt_account_asset_size*/) {
        });
  }

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::TransferAsset &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);
  auto creator_names = splitId(creator_account_id);
  auto &creator_account_name = creator_names.at(0);
  auto &creator_domain_id = creator_names.at(1);

  auto source_names = splitId(command.srcAccountId());
  auto &source_account_name = source_names.at(0);
  auto &source_domain_id = source_names.at(1);

  auto destination_names = splitId(command.destAccountId());
  auto &destination_account_name = destination_names.at(0);
  auto &destination_domain_id = destination_names.at(1);

  auto names = splitId(command.assetId());
  auto &asset_name = names.at(0);
  auto &domain_id = names.at(1);
  auto &amount = command.amount();
  auto &description = command.description();

  if (do_validation) {
    // check if destination account exists
    forAccount<kDbOperation::kGet, kDbEntry::kMustExist>(
        common,
        destination_domain_id,
        destination_account_name,
        [](auto /*account*/, auto /*domain*/) {});

    // get account permissions
    auto destination_permissions = accountPermissions(
        common, destination_domain_id, destination_account_name);
    if (!destination_permissions.isSet(Role::kReceive))
      throw IrohaDbError(22, fmt::format("Not enough permissions"));

    if (command.srcAccountId() != creator_account_id) {
      // check if source account exists
      forAccount<kDbOperation::kGet, kDbEntry::kMustExist>(
          common,
          source_domain_id,
          source_account_name,
          [](auto /*account*/, auto /*domain*/) {});

      GrantablePermissionSet granted_account_permissions;
      if (auto opt_permissions = forGrantablePermissions(
              common,
              creator_domain_id,
              creator_account_name,
              source_domain_id,
              source_account_name,
              [](auto /*account*/,
                 auto /*domain*/,
                 auto /*grantee_account*/,
                 auto /*grantee_domain*/,
                 auto opt_permissions) { return opt_permissions; })) {
        granted_account_permissions = std::move(*opt_permissions);
      }

      checkPermissions(creator_permissions,
                       granted_account_permissions,
                       Role::kRoot,
                       Grantable::kTransferMyAssets);
    } else
      checkPermissions(creator_permissions, Role::kTransfer);

    // check if asset exists
    forAsset<kDbOperation::kGet, kDbEntry::kMustExist>(
        common,
        domain_id,
        asset_name,
        [](auto /*asset*/, auto /*domain*/, auto /*precision*/) {});

    auto status = common.get(fmtstrings::kSetting,
                             iroha::ametsuchi::kMaxDescriptionSizeKey);
    canExist(status, [&] { return fmt::format("Max description size key"); });

    if (status.ok()) {
      uint64_t max_description_size;
      common.decode(max_description_size);
      if (description.size() > max_description_size)
        throw IrohaDbError(23, fmt::format("Too big description"));
    }
  }

  shared_model::interface::Amount source_balance(
      forAccountAssets<kDbOperation::kGet, kDbEntry::kMustExist>(
          common,
          source_domain_id,
          source_account_name,
          command.assetId(),
          [](auto /*account*/,
             auto /*domain*/,
             auto /*asset*/,
             auto opt_amount) {
            assert(opt_amount);
            return *opt_amount;
          }));

  source_balance -= amount;
  if (source_balance.toStringRepr()[0] == 'N')
    throw IrohaDbError(24, fmt::format("Not enough assets"));

  uint64_t account_asset_size(forAccountAssetSize(
      common,
      destination_domain_id,
      destination_account_name,
      [](auto /*account*/, auto /*domain*/, auto opt_account_asset_size) {
        if (opt_account_asset_size)
          return *opt_account_asset_size;
        return uint64_t(0ull);
      }));

  shared_model::interface::Amount destination_balance(
      source_balance.precision());
  if (auto opt_amount =
          forAccountAssets<kDbOperation::kGet, kDbEntry::kCanExist>(
              common,
              source_domain_id,
              source_account_name,
              command.assetId(),
              [](auto /*account*/,
                 auto /*domain*/,
                 auto /*asset*/,
                 auto opt_amount) { return opt_amount; })) {
    destination_balance = *opt_amount;
  } else
    ++account_asset_size;

  destination_balance += amount;
  if (destination_balance.toStringRepr()[0] == 'N')
    throw IrohaDbError(25, fmt::format("Incorrect balance"));

  common.valueBuffer().assign(source_balance.toStringRepr());
  forAccountAssets<kDbOperation::kPut>(common,
                                       source_domain_id,
                                       source_account_name,
                                       command.assetId(),
                                       [](auto /*account*/,
                                          auto /*domain*/,
                                          auto /*asset*/,
                                          auto /*opt_amount*/) {});

  common.valueBuffer().assign(destination_balance.toStringRepr());
  forAccountAssets<kDbOperation::kPut>(common,
                                       destination_domain_id,
                                       destination_account_name,
                                       command.assetId(),
                                       [](auto /*account*/,
                                          auto /*domain*/,
                                          auto /*asset*/,
                                          auto /*opt_amount*/) {});

  common.encode(account_asset_size);
  forAccountAssetSize<kDbOperation::kPut>(
      common,
      destination_domain_id,
      destination_account_name,
      [](auto /*account*/, auto /*domain*/, auto /*opt_account_asset_size*/) {
      });

  return {};
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetSettingValue &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &,
    shared_model::interface::types::CommandIndexType,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  RocksDbCommon common(db_context_);

  auto &key = command.key();
  auto &value = command.value();

  common.valueBuffer().assign(value);
  forSettings<kDbOperation::kPut>(
      common, key, [](auto /*key*/, auto /*opt_value*/) {});

  return {};
}
