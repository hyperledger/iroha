/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_TRANSACTION_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_TRANSACTION_VALIDATOR_HPP

#include <boost/format.hpp>
#include <boost/variant.hpp>

#include "interfaces/commands/add_asset_quantity.hpp"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/commands/add_signatory.hpp"
#include "interfaces/commands/append_role.hpp"
#include "interfaces/commands/command.hpp"
#include "interfaces/commands/create_account.hpp"
#include "interfaces/commands/create_asset.hpp"
#include "interfaces/commands/create_domain.hpp"
#include "interfaces/commands/create_role.hpp"
#include "interfaces/commands/detach_role.hpp"
#include "interfaces/commands/grant_permission.hpp"
#include "interfaces/commands/remove_signatory.hpp"
#include "interfaces/commands/revoke_permission.hpp"
#include "interfaces/commands/set_account_detail.hpp"
#include "interfaces/commands/set_quorum.hpp"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/commands/transfer_asset.hpp"
#include "interfaces/transaction.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/answer.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Visitor used by transaction validator to validate each command
     * @tparam FieldValidator - field validator type
     * @note this class is not thread safe and never going to be
     * so copy constructor and assignment operator are disabled explicitly
     */
    template <typename FieldValidator>
    class CommandValidatorVisitor
        : public boost::static_visitor<ReasonsGroupType> {
      CommandValidatorVisitor(FieldValidator validator)
          : validator_(std::move(validator)) {}

     public:
      CommandValidatorVisitor(const CommandValidatorVisitor &) = delete;
      CommandValidatorVisitor &operator=(const CommandValidatorVisitor &) =
          delete;

      CommandValidatorVisitor(std::shared_ptr<ValidatorsConfig> config)
          : CommandValidatorVisitor(FieldValidator{std::move(config)}) {}

      ReasonsGroupType operator()(
          const interface::AddAssetQuantity &aaq) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "AddAssetQuantity");

        validator_.validateAssetId(reason, aaq.assetId());
        validator_.validateAmount(reason, aaq.amount());

        return reason;
      }

      ReasonsGroupType operator()(const interface::AddPeer &ap) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "AddPeer");

        validator_.validatePeer(reason, ap.peer());

        return reason;
      }

      ReasonsGroupType operator()(const interface::AddSignatory &as) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "AddSignatory");

        validator_.validateAccountId(reason, as.accountId());
        validator_.validatePubkey(reason, as.pubkey());

        return reason;
      }

      ReasonsGroupType operator()(const interface::AppendRole &ar) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "AppendRole");

        validator_.validateAccountId(reason, ar.accountId());
        validator_.validateRoleId(reason, ar.roleName());

        return reason;
      }

      ReasonsGroupType operator()(const interface::CreateAccount &ca) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "CreateAccount");

        validator_.validatePubkey(reason, ca.pubkey());
        validator_.validateAccountName(reason, ca.accountName());
        validator_.validateDomainId(reason, ca.domainId());

        return reason;
      }

      ReasonsGroupType operator()(const interface::CreateAsset &ca) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "CreateAsset");

        validator_.validateAssetName(reason, ca.assetName());
        validator_.validateDomainId(reason, ca.domainId());
        validator_.validatePrecision(reason, ca.precision());

        return reason;
      }

      ReasonsGroupType operator()(const interface::CreateDomain &cd) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "CreateDomain");

        validator_.validateDomainId(reason, cd.domainId());
        validator_.validateRoleId(reason, cd.userDefaultRole());

        return reason;
      }

      ReasonsGroupType operator()(const interface::CreateRole &cr) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "CreateRole");

        validator_.validateRoleId(reason, cr.roleName());
        cr.rolePermissions().iterate([&reason, this](auto i) {
          validator_.validateRolePermission(reason, i);
        });

        return reason;
      }

      ReasonsGroupType operator()(const interface::DetachRole &dr) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "DetachRole");

        validator_.validateAccountId(reason, dr.accountId());
        validator_.validateRoleId(reason, dr.roleName());

        return reason;
      }

      ReasonsGroupType operator()(const interface::GrantPermission &gp) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "GrantPermission");

        validator_.validateAccountId(reason, gp.accountId());
        validator_.validateGrantablePermission(reason, gp.permissionName());

        return reason;
      }

      ReasonsGroupType operator()(const interface::RemoveSignatory &rs) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "RemoveSignatory");

        validator_.validateAccountId(reason, rs.accountId());
        validator_.validatePubkey(reason, rs.pubkey());

        return reason;
      }
      ReasonsGroupType operator()(const interface::RevokePermission &rp) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "RevokePermission");

        validator_.validateAccountId(reason, rp.accountId());
        validator_.validateGrantablePermission(reason, rp.permissionName());

        return reason;
      }

      ReasonsGroupType operator()(
          const interface::SetAccountDetail &sad) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "SetAccountDetail");

        validator_.validateAccountId(reason, sad.accountId());
        validator_.validateAccountDetailKey(reason, sad.key());
        validator_.validateAccountDetailValue(reason, sad.value());

        return reason;
      }

      ReasonsGroupType operator()(const interface::SetQuorum &sq) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "SetQuorum");

        validator_.validateAccountId(reason, sq.accountId());
        validator_.validateQuorum(reason, sq.newQuorum());

        return reason;
      }

      ReasonsGroupType operator()(
          const interface::SubtractAssetQuantity &saq) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "SubtractAssetQuantity");

        validator_.validateAssetId(reason, saq.assetId());
        validator_.validateAmount(reason, saq.amount());

        return reason;
      }

      ReasonsGroupType operator()(const interface::TransferAsset &ta) const {
        ReasonsGroupType reason;
        addInvalidCommand(reason, "TransferAsset");

        if (ta.srcAccountId() == ta.destAccountId()) {
          reason.second.emplace_back(
              "Source and destination accounts cannot be the same");
        }

        validator_.validateAccountId(reason, ta.srcAccountId());
        validator_.validateAccountId(reason, ta.destAccountId());
        validator_.validateAssetId(reason, ta.assetId());
        validator_.validateAmount(reason, ta.amount());
        validator_.validateDescription(reason, ta.description());

        return reason;
      }

     private:
      FieldValidator validator_;
      mutable int command_counter{0};

      // adds command to a reason, appends and increments counter
      void addInvalidCommand(ReasonsGroupType &reason,
                             const std::string &command_name) const {
        reason.first =
            (boost::format("%d %s") % command_counter % command_name).str();
        command_counter++;
      }
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
      Answer validateImpl(const interface::Transaction &tx,
                          CreatedTimeValidator &&validator) const {
        Answer answer;
        std::string tx_reason_name = "Transaction";
        ReasonsGroupType tx_reason(tx_reason_name, GroupedReasons());

        if (tx.commands().empty()) {
          tx_reason.second.push_back(
              "Transaction should contain at least one command");
        }

        field_validator_.validateCreatorAccountId(tx_reason,
                                                  tx.creatorAccountId());
        std::forward<CreatedTimeValidator>(validator)(tx_reason,
                                                      tx.createdTime());
        field_validator_.validateQuorum(tx_reason, tx.quorum());
        if (tx.batchMeta() != boost::none)
          field_validator_.validateBatchMeta(tx_reason, **tx.batchMeta());

        if (not tx_reason.second.empty()) {
          answer.addReason(std::move(tx_reason));
        }

        for (const auto &command : tx.commands()) {
          auto reason = boost::apply_visitor(
              CommandValidator(validators_config_), command.get());
          if (not reason.second.empty()) {
            answer.addReason(std::move(reason));
          }
        }

        return answer;
      }

      explicit TransactionValidator(const FieldValidator &field_validator)
          : field_validator_(field_validator) {}

     public:
      explicit TransactionValidator(std::shared_ptr<ValidatorsConfig> config)
          : TransactionValidator(FieldValidator{config}) {}

      /**
       * Applies validation to given transaction
       * @param tx - transaction to validate
       * @return Answer containing found error if any
       */
      Answer validate(const interface::Transaction &tx) const override {
        return validateImpl(tx, [this](auto &reason, auto time) {
          field_validator_.validateCreatedTime(reason, time);
        });
      }

      /**
       * Validates transaction against current_timestamp instead of time
       * provider
       */
      Answer validate(const interface::Transaction &tx,
                      interface::types::TimestampType current_timestamp) const {
        return validateImpl(tx,
                            [this, current_timestamp](auto &reason, auto time) {
                              field_validator_.validateCreatedTime(
                                  reason, time, current_timestamp);
                            });
      }

     protected:
      FieldValidator field_validator_;
      std::shared_ptr<ValidatorsConfig> validators_config_;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_TRANSACTION_VALIDATOR_HPP
