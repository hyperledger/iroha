/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_AMETSUCHI_COMMAND_EXECUTOR_HPP
#define IROHA_AMETSUCHI_COMMAND_EXECUTOR_HPP

#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class AddAssetQuantity;
    class AddPeer;
    class AddSignatory;
    class AppendRole;
    class Command;
    class CreateAccount;
    class CreateAsset;
    class CreateDomain;
    class CreateRole;
    class DetachRole;
    class GrantPermission;
    class RemoveSignatory;
    class RevokePermission;
    class SetAccountDetail;
    class SetQuorum;
    class SubtractAssetQuantity;
    class TransferAsset;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace ametsuchi {

    /**
     * Error for command execution or validation
     * Contains command name, as well as an error message
     */
    struct CommandError {
      using ErrorCodeType = uint32_t;

      std::string command_name;
      ErrorCodeType error_code;
      std::string error_extra;

      std::string toString() const;
    };

    /**
     *  If command is successful, we assume changes are made,
     *  and do not need anything
     *  If something goes wrong, Result will contain Error
     *  with additional information
     */
    using CommandResult = expected::Result<void, CommandError>;

    class CommandExecutor : public boost::static_visitor<CommandResult> {
     public:
      virtual ~CommandExecutor() = default;

      CommandResult execute(const shared_model::interface::Command &cmd);

      virtual void setCreatorAccountId(
          const shared_model::interface::types::AccountIdType
              &creator_account_id) = 0;

      virtual void doValidation(bool do_validation) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::AddAssetQuantity &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::AddPeer &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::AddSignatory &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::AppendRole &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::CreateAccount &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::CreateAsset &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::CreateDomain &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::CreateRole &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::DetachRole &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::GrantPermission &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::RemoveSignatory &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::RevokePermission &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::SetAccountDetail &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::SetQuorum &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::SubtractAssetQuantity &command) = 0;

      virtual CommandResult operator()(
          const shared_model::interface::TransferAsset &command) = 0;
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_AMETSUCHI_COMMAND_EXECUTOR_HPP
