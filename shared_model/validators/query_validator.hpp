/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_QUERY_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_QUERY_VALIDATOR_HPP

#include <boost/variant/apply_visitor.hpp>
#include <boost/variant/static_visitor.hpp>

#include "common/bind.hpp"
#include "interfaces/queries/get_account.hpp"
#include "interfaces/queries/get_account_asset_transactions.hpp"
#include "interfaces/queries/get_account_assets.hpp"
#include "interfaces/queries/get_account_detail.hpp"
#include "interfaces/queries/get_account_transactions.hpp"
#include "interfaces/queries/get_asset_info.hpp"
#include "interfaces/queries/get_block.hpp"
#include "interfaces/queries/get_engine_receipts.hpp"
#include "interfaces/queries/get_pending_transactions.hpp"
#include "interfaces/queries/get_role_permissions.hpp"
#include "interfaces/queries/get_roles.hpp"
#include "interfaces/queries/get_signatories.hpp"
#include "interfaces/queries/get_transactions.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/validation_error_helpers.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Visitor used by query validator to validate each concrete query
     * @tparam FieldValidator - field validator type
     */
    template <typename FieldValidator>
    class QueryValidatorVisitor
        : public boost::static_visitor<std::optional<ValidationError>> {
      QueryValidatorVisitor(FieldValidator validator)
          : validator_(std::move(validator)) {}

     public:
      // todo igor-egorov 05.04.2018 IR-439 Remove ValidatorsConfig from
      // FieldValidator => and from QueryValidatorVisitor too
      QueryValidatorVisitor(std::shared_ptr<ValidatorsConfig> config)
          : QueryValidatorVisitor(FieldValidator{std::move(config)}) {}

      std::optional<ValidationError> operator()(
          const interface::GetAccount &get_account) const {
        return aggregateErrors(
            "GetAccount",
            {},
            {validator_.validateAccountId(get_account.accountId())});
      }

      std::optional<ValidationError> operator()(
          const interface::GetBlock &get_block) const {
        return aggregateErrors(
            "GetBlock", {}, {validator_.validateHeight(get_block.height())});
      }

      std::optional<ValidationError> operator()(
          const interface::GetSignatories &get_signatories) const {
        return aggregateErrors(
            "GetSignatories",
            {},
            {validator_.validateAccountId(get_signatories.accountId())});
      }

      std::optional<ValidationError> operator()(
          const interface::GetAccountTransactions &get_account_transactions)
          const {
        return aggregateErrors(
            "GetAccountTransactions",
            {},
            {validator_.validateAccountId(get_account_transactions.accountId()),
             validator_.validateTxPaginationMeta(
                 get_account_transactions.paginationMeta())});
      }

      std::optional<ValidationError> operator()(
          const interface::GetAccountAssetTransactions
              &get_account_asset_transactions) const {
        return aggregateErrors(
            "GetAccountAssetTransactions",
            {},
            {validator_.validateAccountId(
                 get_account_asset_transactions.accountId()),
             validator_.validateAssetId(
                 get_account_asset_transactions.assetId()),
             validator_.validateTxPaginationMeta(
                 get_account_asset_transactions.paginationMeta())});
      }

      std::optional<ValidationError> operator()(
          const interface::GetTransactions &get_transactions) const {
        ValidationErrorCreator error_creator;

        const auto &hashes = get_transactions.transactionHashes();
        if (hashes.size() == 0) {
          error_creator.addReason("tx_hashes cannot be empty");
        }

        for (const auto &h : hashes) {
          error_creator |= validator_.validateHash(h);
        }

        return std::move(error_creator).getValidationError("GetTransactions");
      }

      std::optional<ValidationError> operator()(
          const interface::GetAccountAssets &get_account_assets) const {
        using iroha::operator|;
        return aggregateErrors(
            "GetAccountAssets",
            {},
            {validator_.validateAccountId(get_account_assets.accountId()),
             get_account_assets.paginationMeta() |
                 [this](const auto &pagination_meta) {
                   return validator_.validateAssetPaginationMeta(
                       pagination_meta);
                 }});
      }

      std::optional<ValidationError> operator()(
          const interface::GetAccountDetail &get_account_detail) const {
        using iroha::operator|;
        return aggregateErrors(
            "GetAccountDetail",
            {},
            {validator_.validateAccountId(get_account_detail.accountId()),
             get_account_detail.key() |
                 [this](const auto &key) {
                   return validator_.validateAccountDetailKey(key);
                 },
             get_account_detail.writer() |
                 [this](const auto &writer) {
                   return validator_.validateAccountId(writer);
                 },
             get_account_detail.paginationMeta() |
                 [this](const auto &pagination_meta) {
                   return validator_.validateAccountDetailPaginationMeta(
                       pagination_meta);
                 }});
      }

      std::optional<ValidationError> operator()(
          const interface::GetRoles &get_roles) const {
        return std::nullopt;
      }

      std::optional<ValidationError> operator()(
          const interface::GetRolePermissions &get_role_permissions) const {
        return aggregateErrors(
            "GetRolePermissions",
            {},
            {validator_.validateRoleId(get_role_permissions.roleId())});
      }

      std::optional<ValidationError> operator()(
          const interface::GetAssetInfo &get_asset_info) const {
        return aggregateErrors(
            "GetAssetInfo",
            {},
            {validator_.validateAssetId(get_asset_info.assetId())});
      }

      std::optional<ValidationError> operator()(
          const interface::GetPendingTransactions &get_pending_transactions)
          const {
        using iroha::operator|;
        return aggregateErrors(
            "GetPendingTransactions",
            {},
            {// TODO igor-egorov 2019-06-06 IR-516 Make meta non-optional
             get_pending_transactions.paginationMeta() |
             [this](const auto &pagination_meta) {
               return validator_.validateTxPaginationMeta(pagination_meta);
             }});
      }

      std::optional<ValidationError> operator()(
          const interface::GetPeers &get_peers) const {
        return std::nullopt;
      }

      std::optional<ValidationError> operator()(
          const interface::GetEngineReceipts &qry) const {
        return validator_.validateHash(
            crypto::Hash::fromHexString(qry.txHash()));
      }

     private:
      FieldValidator validator_;
    };

    /**
     * Class that validates query field from query
     * @tparam FieldValidator - field validator type
     * @tparam QueryFieldValidator - concrete query validator type
     */
    template <typename FieldValidator, typename QueryFieldValidator>
    class QueryValidator : public AbstractValidator<interface::Query> {
      QueryValidator(const FieldValidator &field_validator,
                     const QueryFieldValidator &query_field_validator)
          : field_validator_(field_validator),
            query_field_validator_(query_field_validator) {}

     public:
      QueryValidator(std::shared_ptr<ValidatorsConfig> config)
          : QueryValidator(FieldValidator{config},
                           QueryFieldValidator{config}) {}

      /**
       * Applies validation to given query
       * @param qry - query to validate
       * @return found error if any
       */
      std::optional<ValidationError> validate(
          const interface::Query &qry) const override {
        ValidationErrorCreator error_creator;

        error_creator |=
            field_validator_.validateCreatorAccountId(qry.creatorAccountId());
        error_creator |=
            field_validator_.validateCreatedTime(qry.createdTime());
        error_creator |= field_validator_.validateCounter(qry.queryCounter());
        error_creator |=
            boost::apply_visitor(query_field_validator_, qry.get());

        return std::move(error_creator).getValidationError("Query");
      }

     protected:
      FieldValidator field_validator_;
      QueryFieldValidator query_field_validator_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_QUERY_VALIDATOR_HPP
