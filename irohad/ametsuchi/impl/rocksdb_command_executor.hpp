/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROCKSDB_COMMAND_EXECUTOR_HPP
#define IROHA_ROCKSDB_COMMAND_EXECUTOR_HPP

#include <optional>

#include <fmt/format.h>
#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/rocksdb_common.hpp"
#include "ametsuchi/impl/rocksdb_db_transaction.hpp"
#include "interfaces/permissions.hpp"

namespace rocksdb {
  class Transaction;
}

namespace shared_model::interface {
  class AddAssetQuantity;
  class AddPeer;
  class AddSignatory;
  class AppendRole;
  class CompareAndSetAccountDetail;
  class CallEngine;
  class CreateAccount;
  class CreateAsset;
  class CreateDomain;
  class CreateRole;
  class DetachRole;
  class GrantPermission;
  class PermissionToString;
  class RemovePeer;
  class RemoveSignatory;
  class RevokePermission;
  class SetAccountDetail;
  class SetQuorum;
  class SubtractAssetQuantity;
  class TransferAsset;
  class SetSettingValue;
}  // namespace shared_model::interface

namespace iroha::ametsuchi {

  class RocksDbSpecificQueryExecutor;
  class VmCaller;

  class RocksDbCommandExecutor final : public CommandExecutor {
   public:
    using ExecutionResult = expected::Result<void, DbError>;

    enum ErrorCodes {
      kNotConfigured = 1,
      kNoPermissions = 2,
      kNoAccount = 3,
      kInvalidAmount = 3,
      kRoleAlreadyExists = 3,
      kSignatoryMustNotExist = 3,
      kInvalidAssetAmount = 4,
      kIncorrectOldValue = 4,
      kPeersCountIsNotEnough = 4,
      kNoSignatory = 4,
      kCountNotEnough = 5,
      kNotEnoughAssets = 6,
      kIncorrectBalance = 7,
      kException = 1002,
      kNoImplementation = 1005,
      kPermissionIsAlreadySet = 1007,
      kPublicKeyIsEmpty = 1008,
      kInvalidFieldSize = 1009,
    };

    RocksDbCommandExecutor(
        std::shared_ptr<RocksDBContext> db_context,
        std::shared_ptr<shared_model::interface::PermissionToString>
            perm_converter,
        std::shared_ptr<RocksDbSpecificQueryExecutor> specific_query_executor,
        std::optional<std::reference_wrapper<const VmCaller>> vm_caller);

    ~RocksDbCommandExecutor();

    CommandResult execute(
        const shared_model::interface::Command &cmd,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation) override;

    void skipChanges() override;
    DatabaseTransaction &dbSession() override;
    std::shared_ptr<RocksDBContext> getSession();

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::AddAssetQuantity &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::AddPeer &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::AddSignatory &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::CallEngine &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::AppendRole &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::CompareAndSetAccountDetail &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::CreateAccount &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::CreateAsset &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::CreateDomain &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::CreateRole &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::DetachRole &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::GrantPermission &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::RemovePeer &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::RemoveSignatory &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::RevokePermission &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::SetAccountDetail &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::SetQuorum &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::SubtractAssetQuantity &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::TransferAsset &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &tx_hash,
        shared_model::interface::types::CommandIndexType cmd_index,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

    ExecutionResult operator()(
        RocksDbCommon &common,
        const shared_model::interface::SetSettingValue &command,
        const shared_model::interface::types::AccountIdType &creator_account_id,
        const std::string &,
        shared_model::interface::types::CommandIndexType,
        bool do_validation,
        shared_model::interface::RolePermissionSet const &creator_permissions);

   private:
    std::shared_ptr<RocksDBContext> db_context_;
    std::shared_ptr<shared_model::interface::PermissionToString>
        perm_converter_;
    std::shared_ptr<RocksDbSpecificQueryExecutor> specific_query_executor_;
    std::optional<std::reference_wrapper<const VmCaller>> vm_caller_;
    RocksDbTransaction db_transaction_;
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_ROCKSDB_COMMAND_EXECUTOR_HPP
