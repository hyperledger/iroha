/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TRANSACTION_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_TRANSACTION_VALIDATOR_HPP

#include <boost/range/adaptor/indexed.hpp>
#include <boost/variant.hpp>

#include "common/bind.hpp"
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
#include "interfaces/transaction.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/validation_error_helpers.hpp"
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    struct ValidatorsConfig;

    /**
     * Visitor used by transaction validator to validate each command
     * @tparam FieldValidator - field validator type
     * @note this class is not thread safe and never going to be
     * so copy constructor and assignment operator are disabled explicitly
     */
    template <typename FieldValidator>
    class CommandValidatorVisitor
        : public boost::static_visitor<std::optional<ValidationError>> {
      CommandValidatorVisitor(FieldValidator validator)
          : validator_(std::move(validator)) {}

     public:
      CommandValidatorVisitor(std::shared_ptr<ValidatorsConfig> config)
          : CommandValidatorVisitor(FieldValidator{std::move(config)}) {}

      std::optional<ValidationError> operator()(
          const interface::AddAssetQuantity &add_asset_quantity) const {
        return aggregateErrors(
            "AddAssetQuantity",
            {},
            {validator_.validateAssetId(add_asset_quantity.assetId()),
             validator_.validateAmount(add_asset_quantity.amount())});
      }

      std::optional<ValidationError> operator()(
          const interface::AddPeer &add_peer) const {
        return aggregateErrors(
            "AddPeer", {}, {validator_.validatePeer(add_peer.peer())});
      }

      std::optional<ValidationError> operator()(
          const interface::AddSignatory &add_signatory) const {
        return aggregateErrors(
            "AddSignatory",
            {},
            {validator_.validateAccountId(add_signatory.accountId()),
             validator_.validatePubkey(add_signatory.pubkey())});
      }

      std::optional<ValidationError> operator()(
          const interface::CallEngine &call_engine) const {
        ValidationErrorCreator error_creator;
        error_creator |= validator_.validateAccountId(call_engine.caller());
        if (call_engine.callee()) {
          error_creator |= validator_.validateEvmHexAddress(
              call_engine.callee().value().get());
        }
        error_creator |= validator_.validateBytecode(
            interface::types::EvmCodeHexStringView{call_engine.input()});
        return std::move(error_creator).getValidationError("CallEngine");
      }

      std::optional<ValidationError> operator()(
          const interface::AppendRole &append_role) const {
        return aggregateErrors(
            "AppendRole",
            {},
            {validator_.validateAccountId(append_role.accountId()),
             validator_.validateRoleId(append_role.roleName())});
      }

      std::optional<ValidationError> operator()(
          const interface::CreateAccount &create_account) const {
        return aggregateErrors(
            "CreateAccount",
            {},
            {validator_.validatePubkey(create_account.pubkey()),
             validator_.validateAccountName(create_account.accountName()),
             validator_.validateDomainId(create_account.domainId())});
      }

      std::optional<ValidationError> operator()(
          const interface::CreateAsset &create_asset) const {
        return aggregateErrors(
            "CreateAsset",
            {},
            {validator_.validateAssetName(create_asset.assetName()),
             validator_.validateDomainId(create_asset.domainId()),
             validator_.validatePrecision(create_asset.precision())});
      }

      std::optional<ValidationError> operator()(
          const interface::CreateDomain &create_domain) const {
        return aggregateErrors(
            "CreateDomain",
            {},
            {validator_.validateDomainId(create_domain.domainId()),
             validator_.validateRoleId(create_domain.userDefaultRole())});
      }

      std::optional<ValidationError> operator()(
          const interface::CreateRole &create_role) const {
        ValidationErrorCreator error_creator;
        error_creator |= validator_.validateRoleId(create_role.roleName());

        create_role.rolePermissions().iterate([&error_creator, this](auto i) {
          error_creator |= validator_.validateRolePermission(i);
        });
        return std::move(error_creator).getValidationError("CreateRole");
      }

      std::optional<ValidationError> operator()(
          const interface::DetachRole &detach_role) const {
        return aggregateErrors(
            "DetachRole",
            {},
            {validator_.validateAccountId(detach_role.accountId()),
             validator_.validateRoleId(detach_role.roleName())});
      }

      std::optional<ValidationError> operator()(
          const interface::GrantPermission &grant_permission) const {
        return aggregateErrors(
            "GrantPermission",
            {},
            {validator_.validateAccountId(grant_permission.accountId()),
             validator_.validateGrantablePermission(
                 grant_permission.permissionName())});
      }

      std::optional<ValidationError> operator()(
          const interface::RemovePeer &remove_peer) const {
        return aggregateErrors(
            "RemovePeer",
            {},
            {validator_.validatePubkey(remove_peer.pubkey())});
      }

      std::optional<ValidationError> operator()(
          const interface::RemoveSignatory &remove_signatory) const {
        return aggregateErrors(
            "RemoveSignatory",
            {},
            {validator_.validateAccountId(remove_signatory.accountId()),
             validator_.validatePubkey(remove_signatory.pubkey())});
      }

      std::optional<ValidationError> operator()(
          const interface::RevokePermission &revoke_permission) const {
        return aggregateErrors(
            "RevokePermission",
            {},
            {validator_.validateAccountId(revoke_permission.accountId()),
             validator_.validateGrantablePermission(
                 revoke_permission.permissionName())});
      }

      std::optional<ValidationError> operator()(
          const interface::SetAccountDetail &set_account_detail) const {
        return aggregateErrors(
            "SetAccountDetail",
            {},
            {validator_.validateAccountId(set_account_detail.accountId()),
             validator_.validateAccountDetailKey(set_account_detail.key()),
             validator_.validateAccountDetailValue(
                 set_account_detail.value())});
      }

      std::optional<ValidationError> operator()(
          const interface::SetQuorum &set_quorum) const {
        return aggregateErrors(
            "SetQuorum",
            {},
            {validator_.validateAccountId(set_quorum.accountId()),
             validator_.validateQuorum(set_quorum.newQuorum())});
      }

      std::optional<ValidationError> operator()(
          const interface::SubtractAssetQuantity &subtract_asset_quantity)
          const {
        return aggregateErrors(
            "SubtractAssetQuantity",
            {},
            {validator_.validateAssetId(subtract_asset_quantity.assetId()),
             validator_.validateAmount(subtract_asset_quantity.amount())});
      }

      std::optional<ValidationError> operator()(
          const interface::TransferAsset &transfer_asset) const {
        return aggregateErrors(
            "TransferAsset",
            {[&]() -> std::optional<std::string> {
              if (transfer_asset.srcAccountId()
                  == transfer_asset.destAccountId()) {
                return std::string{
                    "Source and destination accounts are the same."};
              }
              return std::nullopt;
            }()},
            {validator_.validateAccountId(transfer_asset.srcAccountId()),
             validator_.validateAccountId(transfer_asset.destAccountId()),
             validator_.validateAssetId(transfer_asset.assetId()),
             validator_.validateAmount(transfer_asset.amount()),
             validator_.validateDescription(transfer_asset.description())});
      }

      std::optional<ValidationError> operator()(
          const interface::CompareAndSetAccountDetail
              &compare_and_set_account_detail) const {
        using iroha::operator|;
        return aggregateErrors(
            "CompareAndSetAccountDetail",
            {},
            {validator_.validateAccountId(
                 compare_and_set_account_detail.accountId()),
             validator_.validateAccountDetailKey(
                 compare_and_set_account_detail.key()),
             validator_.validateAccountDetailValue(
                 compare_and_set_account_detail.value()),
             compare_and_set_account_detail.oldValue() |
                 [this](
                     const auto &oldValue) -> std::optional<ValidationError> {
               return this->validator_.validateOldAccountDetailValue(oldValue);
             }});
      }

      std::optional<ValidationError> operator()(
          const interface::SetSettingValue &set_setting_value) const {
        return std::nullopt;
      }

     private:
      FieldValidator validator_;
    };

    /**
     * Class that validates commands from transaction
     * @tparam FieldValidator
     * @tparam CommandValidator
     */
    template <typename FieldValidator, typename CommandValidator>
    class TransactionValidator
        : public AbstractValidator<interface::Transaction> {
     private:
      template <typename CreatedTimeValidator>
      std::optional<ValidationError> validateImpl(
          const interface::Transaction &tx,
          CreatedTimeValidator &&validator) const {
        using iroha::operator|;

        ValidationErrorCreator error_creator;

        if (tx.commands().empty()) {
          error_creator.addReason(
              "Transaction must contain at least one command.");
        }

        error_creator |=
            field_validator_.validateCreatorAccountId(tx.creatorAccountId());
        error_creator |=
            std::forward<CreatedTimeValidator>(validator)(tx.createdTime());
        error_creator |= field_validator_.validateQuorum(tx.quorum());
        error_creator |= tx.batchMeta() | [this](const auto &batch_meta) {
          return field_validator_.validateBatchMeta(*batch_meta);
        };

        for (auto cmd : tx.commands() | boost::adaptors::indexed(1)) {
          boost::apply_visitor(command_validator_visitor_, cmd.value().get()) |
              [&cmd, &error_creator](auto error) {
                error_creator.addChildError(ValidationError{
                    std::string{"Command #"} + std::to_string(cmd.index()),
                    {},
                    {error}});
              };
        }

        return std::move(error_creator).getValidationError("Transaction");
      }

     public:
      explicit TransactionValidator(
          const std::shared_ptr<ValidatorsConfig> &config)
          : field_validator_(config), command_validator_visitor_(config) {}

      /**
       * Applies validation to given transaction
       * @param tx - transaction to validate
       * @return found error if any
       */
      std::optional<ValidationError> validate(
          const interface::Transaction &tx) const override {
        return validateImpl(tx, [this](auto time) {
          return field_validator_.validateCreatedTime(time);
        });
      }

      /**
       * Validates transaction against current_timestamp instead of time
       * provider
       */
      std::optional<ValidationError> validate(
          const interface::Transaction &tx,
          interface::types::TimestampType current_timestamp) const {
        return validateImpl(tx, [this, current_timestamp](auto time) {
          return field_validator_.validateCreatedTime(time, current_timestamp);
        });
      }

     protected:
      FieldValidator field_validator_;
      CommandValidator command_validator_visitor_;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_TRANSACTION_VALIDATOR_HPP
