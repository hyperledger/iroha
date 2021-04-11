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

  // get account asset balance
  if (auto opt_account_assets =
          forAccountAssets(common,
                           creator_domain_id,
                           creator_account_name,
                           command.assetId(),
                           [](auto /*account*/,
                              auto /*domain*/,
                              auto /*asset*/,
                              auto opt_amount) { return opt_amount; }))
    result = std::move(*opt_account_assets);
  else
    ++account_asset_size;

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
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AddSignatory &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::AppendRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CallEngine &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CompareAndSetAccountDetail &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateAccount &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateAsset &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateDomain &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::CreateRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::DetachRole &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::GrantPermission &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RemovePeer &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RemoveSignatory &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::RevokePermission &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetAccountDetail &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetQuorum &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SubtractAssetQuantity &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::TransferAsset &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &tx_hash,
    shared_model::interface::types::CommandIndexType cmd_index,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}

CommandResult RocksDbCommandExecutor::operator()(
    const shared_model::interface::SetSettingValue &command,
    const shared_model::interface::types::AccountIdType &creator_account_id,
    const std::string &,
    shared_model::interface::types::CommandIndexType,
    bool do_validation,
    shared_model::interface::RolePermissionSet const &creator_permissions) {
  throw IrohaDbError(100, fmt::format("Not implemented"));
}
