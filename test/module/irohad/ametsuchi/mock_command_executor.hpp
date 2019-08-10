/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_COMMAND_EXECUTOR_HPP
#define IROHA_MOCK_COMMAND_EXECUTOR_HPP

#include "ametsuchi/command_executor.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    struct MockCommandExecutor : public CommandExecutor {
      MOCK_METHOD1(setCreatorAccountId,
                   void(const shared_model::interface::types::AccountIdType &));

      MOCK_METHOD1(doValidation, void(bool));

      CommandResult operator()(
          const shared_model::interface::AddAssetQuantity &command) override {
        return doAddAssetQuantity(command);
      }

      CommandResult operator()(
          const shared_model::interface::AddPeer &command) override {
        return doAddPeer(command);
      }

      CommandResult operator()(
          const shared_model::interface::AddSignatory &command) override {
        return doAddSignatory(command);
      }

      CommandResult operator()(
          const shared_model::interface::AppendRole &command) override {
        return doAppendRole(command);
      }

      CommandResult operator()(
          const shared_model::interface::CreateAccount &command) override {
        return doCreateAccount(command);
      }

      CommandResult operator()(
          const shared_model::interface::CreateAsset &command) override {
        return doCreateAsset(command);
      }

      CommandResult operator()(
          const shared_model::interface::CreateDomain &command) override {
        return doCreateDomain(command);
      }

      CommandResult operator()(
          const shared_model::interface::CreateRole &command) override {
        return doCreateRole(command);
      }

      CommandResult operator()(
          const shared_model::interface::DetachRole &command) override {
        return doDetachRole(command);
      }

      CommandResult operator()(
          const shared_model::interface::GrantPermission &command) override {
        return doGrantPermission(command);
      }

      CommandResult operator()(
          const shared_model::interface::RemoveSignatory &command) override {
        return doRemoveSignatory(command);
      }

      CommandResult operator()(
          const shared_model::interface::RevokePermission &command) override {
        return doRevokePermission(command);
      }

      CommandResult operator()(
          const shared_model::interface::SetAccountDetail &command) override {
        return doSetAccountDetail(command);
      }

      CommandResult operator()(
          const shared_model::interface::SetQuorum &command) override {
        return doSetQuorum(command);
      }

      CommandResult operator()(
          const shared_model::interface::SubtractAssetQuantity &command)
          override {
        return doSubtractAssetQuantity(command);
      }

      CommandResult operator()(
          const shared_model::interface::TransferAsset &command) override {
        return doTransferAsset(command);
      }

      MOCK_METHOD1(
          doAddAssetQuantity,
          CommandResult(const shared_model::interface::AddAssetQuantity &));

      MOCK_METHOD1(doAddPeer,
                   CommandResult(const shared_model::interface::AddPeer &));

      MOCK_METHOD1(
          doAddSignatory,
          CommandResult(const shared_model::interface::AddSignatory &));

      MOCK_METHOD1(doAppendRole,
                   CommandResult(const shared_model::interface::AppendRole &));

      MOCK_METHOD1(
          doCreateAccount,
          CommandResult(const shared_model::interface::CreateAccount &));

      MOCK_METHOD1(doCreateAsset,
                   CommandResult(const shared_model::interface::CreateAsset &));

      MOCK_METHOD1(
          doCreateDomain,
          CommandResult(const shared_model::interface::CreateDomain &));

      MOCK_METHOD1(doCreateRole,
                   CommandResult(const shared_model::interface::CreateRole &));

      MOCK_METHOD1(doDetachRole,
                   CommandResult(const shared_model::interface::DetachRole &));

      MOCK_METHOD1(
          doGrantPermission,
          CommandResult(const shared_model::interface::GrantPermission &));

      MOCK_METHOD1(
          doRemoveSignatory,
          CommandResult(const shared_model::interface::RemoveSignatory &));

      MOCK_METHOD1(
          doRevokePermission,
          CommandResult(const shared_model::interface::RevokePermission &));

      MOCK_METHOD1(
          doSetAccountDetail,
          CommandResult(const shared_model::interface::SetAccountDetail &));

      MOCK_METHOD1(doSetQuorum,
                   CommandResult(const shared_model::interface::SetQuorum &));

      MOCK_METHOD1(doSubtractAssetQuantity,
                   CommandResult(
                       const shared_model::interface::SubtractAssetQuantity &));

      MOCK_METHOD1(
          doTransferAsset,
          CommandResult(const shared_model::interface::TransferAsset &));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_COMMAND_EXECUTOR_HPP
