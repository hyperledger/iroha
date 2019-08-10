/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_COMMAND_EXECUTOR_HPP
#define IROHA_POSTGRES_COMMAND_EXECUTOR_HPP

#include "ametsuchi/command_executor.hpp"

#include "ametsuchi/impl/soci_utils.hpp"

namespace soci {
  class session;
}

namespace shared_model {
  namespace interface {
    class PermissionToString;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    class PostgresCommandExecutor final : public CommandExecutor {
     public:
      PostgresCommandExecutor(
          soci::session &transaction,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter);

      ~PostgresCommandExecutor();

      void setCreatorAccountId(
          const shared_model::interface::types::AccountIdType
              &creator_account_id) override;

      void doValidation(bool do_validation) override;

      CommandResult operator()(
          const shared_model::interface::AddAssetQuantity &command) override;

      CommandResult operator()(
          const shared_model::interface::AddPeer &command) override;

      CommandResult operator()(
          const shared_model::interface::AddSignatory &command) override;

      CommandResult operator()(
          const shared_model::interface::AppendRole &command) override;

      CommandResult operator()(
          const shared_model::interface::CompareAndSetAccountDetail &command)
          override;

      CommandResult operator()(
          const shared_model::interface::CreateAccount &command) override;

      CommandResult operator()(
          const shared_model::interface::CreateAsset &command) override;

      CommandResult operator()(
          const shared_model::interface::CreateDomain &command) override;

      CommandResult operator()(
          const shared_model::interface::CreateRole &command) override;

      CommandResult operator()(
          const shared_model::interface::DetachRole &command) override;

      CommandResult operator()(
          const shared_model::interface::GrantPermission &command) override;

      CommandResult operator()(
          const shared_model::interface::RemovePeer &command) override;

      CommandResult operator()(
          const shared_model::interface::RemoveSignatory &command) override;

      CommandResult operator()(
          const shared_model::interface::RevokePermission &command) override;

      CommandResult operator()(
          const shared_model::interface::SetAccountDetail &command) override;

      CommandResult operator()(
          const shared_model::interface::SetQuorum &command) override;

      CommandResult operator()(
          const shared_model::interface::SubtractAssetQuantity &command)
          override;

      CommandResult operator()(
          const shared_model::interface::TransferAsset &command) override;

     private:
      class CommandStatements;
      class StatementExecutor;

      void initStatements();

      std::unique_ptr<CommandStatements> makeCommandStatements(
          soci::session &session,
          const std::string &base_statement,
          const std::vector<std::string> &permission_checks);

      soci::session &sql_;
      bool do_validation_;

      shared_model::interface::types::AccountIdType creator_account_id_;
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;

      std::unique_ptr<CommandStatements> add_asset_quantity_statements_;
      std::unique_ptr<CommandStatements> add_peer_statements_;
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
      std::unique_ptr<CommandStatements> remove_signatory_statements_;
      std::unique_ptr<CommandStatements> revoke_permission_statements_;
      std::unique_ptr<CommandStatements> set_account_detail_statements_;
      std::unique_ptr<CommandStatements> set_quorum_statements_;
      std::unique_ptr<CommandStatements> subtract_asset_quantity_statements_;
      std::unique_ptr<CommandStatements> transfer_asset_statements_;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_COMMAND_EXECUTOR_HPP
