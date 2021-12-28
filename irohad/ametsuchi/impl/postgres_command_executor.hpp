/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_COMMAND_EXECUTOR_HPP
#define IROHA_POSTGRES_COMMAND_EXECUTOR_HPP

#include <optional>
#include "ametsuchi/command_executor.hpp"

#include "ametsuchi/impl/postgres_db_transaction.hpp"
#include "ametsuchi/impl/soci_utils.hpp"

namespace soci {
  class session;
}

namespace shared_model {
  namespace interface {
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
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    class PostgresSpecificQueryExecutor;
    class VmCaller;

    class PostgresCommandExecutor final : public CommandExecutor {
     public:
      PostgresCommandExecutor(
          std::unique_ptr<soci::session> sql,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter,
          std::shared_ptr<PostgresSpecificQueryExecutor>
              specific_query_executor,
          std::optional<std::reference_wrapper<const VmCaller>> vm_caller);

      ~PostgresCommandExecutor();

      CommandResult execute(
          const shared_model::interface::Command &cmd,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation) override;

      void skipChanges() override;

      DatabaseTransaction &dbSession() override;

      soci::session &getSession();

      CommandResult operator()(
          const shared_model::interface::AddAssetQuantity &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::AddPeer &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::AddSignatory &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CallEngine &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::AppendRole &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CompareAndSetAccountDetail &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateAccount &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateAsset &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateDomain &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::CreateRole &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::DetachRole &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::GrantPermission &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::RemovePeer &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::RemoveSignatory &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::RevokePermission &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::SetAccountDetail &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::SetQuorum &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::SubtractAssetQuantity &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::TransferAsset &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &tx_hash,
          shared_model::interface::types::CommandIndexType cmd_index,
          bool do_validation);

      CommandResult operator()(
          const shared_model::interface::SetSettingValue &command,
          const shared_model::interface::types::AccountIdType
              &creator_account_id,
          const std::string &,
          shared_model::interface::types::CommandIndexType,
          bool do_validation);

     private:
      class CommandStatements;
      class StatementExecutor;

      void initStatements();

      std::unique_ptr<CommandStatements> makeCommandStatements(
          const std::unique_ptr<soci::session> &session,
          const std::string &base_statement,
          const std::vector<std::string> &permission_checks);

      std::unique_ptr<soci::session> sql_;
      PostgresDbTransaction db_transaction_;

      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;
      std::shared_ptr<PostgresSpecificQueryExecutor> specific_query_executor_;
      std::optional<std::reference_wrapper<const VmCaller>> vm_caller_;

      std::unique_ptr<CommandStatements> add_asset_quantity_statements_;
      std::unique_ptr<CommandStatements> add_peer_statements_;
      std::unique_ptr<CommandStatements> add_sync_peer_statements_;
      std::unique_ptr<CommandStatements> add_signatory_statements_;
      std::unique_ptr<CommandStatements> append_role_statements_;
      std::unique_ptr<CommandStatements>
          compare_and_set_account_detail_statements_;
      std::unique_ptr<CommandStatements> create_account_statements_;
      std::unique_ptr<CommandStatements> create_asset_statements_;
      std::unique_ptr<CommandStatements> create_domain_statements_;
      std::unique_ptr<CommandStatements> create_role_statements_;
      std::unique_ptr<CommandStatements> detach_role_statements_;
      std::unique_ptr<CommandStatements> grant_permission_statements_;
      std::unique_ptr<CommandStatements> remove_peer_statements_;
      std::unique_ptr<CommandStatements> remove_sync_peer_statements_;
      std::unique_ptr<CommandStatements> remove_signatory_statements_;
      std::unique_ptr<CommandStatements> revoke_permission_statements_;
      std::unique_ptr<CommandStatements> set_account_detail_statements_;
      std::unique_ptr<CommandStatements> set_quorum_statements_;
      std::unique_ptr<CommandStatements> store_engine_response_statements_;
      std::unique_ptr<CommandStatements> subtract_asset_quantity_statements_;
      std::unique_ptr<CommandStatements> transfer_asset_statements_;
      std::unique_ptr<CommandStatements> set_setting_value_statements_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_COMMAND_EXECUTOR_HPP
