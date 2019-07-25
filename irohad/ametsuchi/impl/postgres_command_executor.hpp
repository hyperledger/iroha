/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_POSTGRES_COMMAND_EXECUTOR_HPP
#define IROHA_POSTGRES_COMMAND_EXECUTOR_HPP

#include "ametsuchi/command_executor.hpp"
#include "ametsuchi/impl/soci_utils.hpp"

namespace shared_model {
  namespace interface {
    class PermissionToString;
  }
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    class PostgresCommandExecutor : public CommandExecutor {
     public:
      PostgresCommandExecutor(
          soci::session &transaction,
          std::shared_ptr<shared_model::interface::PermissionToString>
              perm_converter);

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

      CommandResult operator()(
          const shared_model::interface::CompareAndSetAccountDetail &command)
          override;

      static void prepareStatements(soci::session &sql);

     private:
      soci::session &sql_;
      bool do_validation_;

      shared_model::interface::types::AccountIdType creator_account_id_;
      std::shared_ptr<shared_model::interface::PermissionToString>
          perm_converter_;

      // 14.09.18 nickaleks: IR-1708 Load SQL from separate files
      static const std::string addAssetQuantityBase;
      static const std::string addPeerBase;
      static const std::string addSignatoryBase;
      static const std::string appendRoleBase;
      static const std::string createAccountBase;
      static const std::string createAssetBase;
      static const std::string createDomainBase;
      static const std::string createRoleBase;
      static const std::string detachRoleBase;
      static const std::string grantPermissionBase;
      static const std::string removePeerBase;
      static const std::string removeSignatoryBase;
      static const std::string revokePermissionBase;
      static const std::string setAccountDetailBase;
      static const std::string setQuorumBase;
      static const std::string subtractAssetQuantityBase;
      static const std::string transferAssetBase;
      static const std::string compareAndSetAccountDetailBase;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_POSTGRES_COMMAND_EXECUTOR_HPP
