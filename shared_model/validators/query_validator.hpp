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
#include "interfaces/queries/get_pending_transactions.hpp"
#include "interfaces/queries/get_role_permissions.hpp"
#include "interfaces/queries/get_roles.hpp"
#include "interfaces/queries/get_signatories.hpp"
#include "interfaces/queries/get_transactions.hpp"
#include "interfaces/queries/query.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"
#include "validators/abstract_validator.hpp"
#include "validators/answer.hpp"

namespace shared_model {
  namespace validation {

    /**
     * Visitor used by query validator to validate each concrete query
     * @tparam FieldValidator - field validator type
     */
    template <typename FieldValidator>
    class QueryValidatorVisitor
        : public boost::static_visitor<ReasonsGroupType> {
      QueryValidatorVisitor(FieldValidator validator)
          : validator_(std::move(validator)) {}

     public:
      // todo igor-egorov 05.04.2018 IR-439 Remove ValidatorsConfig from
      // FieldValidator => and from QueryValidatorVisitor too
      QueryValidatorVisitor(std::shared_ptr<ValidatorsConfig> config)
          : QueryValidatorVisitor(FieldValidator{std::move(config)}) {}

      ReasonsGroupType operator()(const interface::GetAccount &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetAccount";

        validator_.validateAccountId(reason, qry.accountId());

        return reason;
      }

      ReasonsGroupType operator()(const interface::GetBlock &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetBlock";

        validator_.validateHeight(reason, qry.height());

        return reason;
      }

      ReasonsGroupType operator()(const interface::GetSignatories &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetSignatories";

        validator_.validateAccountId(reason, qry.accountId());

        return reason;
      }

      ReasonsGroupType operator()(
          const interface::GetAccountTransactions &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetAccountTransactions";

        validator_.validateAccountId(reason, qry.accountId());
        validator_.validateTxPaginationMeta(reason, qry.paginationMeta());

        return reason;
      }

      ReasonsGroupType operator()(
          const interface::GetAccountAssetTransactions &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetAccountAssetTransactions";

        validator_.validateAccountId(reason, qry.accountId());
        validator_.validateAssetId(reason, qry.assetId());
        validator_.validateTxPaginationMeta(reason, qry.paginationMeta());

        return reason;
      }

      ReasonsGroupType operator()(const interface::GetTransactions &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetTransactions";

        const auto &hashes = qry.transactionHashes();
        if (hashes.size() == 0) {
          reason.second.push_back("tx_hashes cannot be empty");
        }

        for (const auto &h : hashes) {
          validator_.validateHash(reason, h);
        }

        return reason;
      }

      ReasonsGroupType operator()(
          const interface::GetAccountAssets &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetAccountAssets";

        validator_.validateAccountId(reason, qry.accountId());
        if (qry.paginationMeta()) {
          validator_.validateAssetPaginationMeta(reason, *qry.paginationMeta());
        }
        return reason;
      }

      ReasonsGroupType operator()(
          const interface::GetAccountDetail &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetAccountDetail";

        using iroha::operator|;

        validator_.validateAccountId(reason, qry.accountId());
        qry.key() | [&reason, this](const auto &key) {
          this->validator_.validateAccountDetailKey(reason, key);
        };
        qry.writer() | [&reason, this](const auto &writer) {
          this->validator_.validateAccountId(reason, writer);
        };
        qry.paginationMeta() | [&reason, this](const auto &pagination_meta) {
          this->validator_.validateAccountDetailPaginationMeta(reason,
                                                               pagination_meta);
        };

        return reason;
      }

      ReasonsGroupType operator()(const interface::GetRoles &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetRoles";

        return reason;
      }

      ReasonsGroupType operator()(
          const interface::GetRolePermissions &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetRolePermissions";

        validator_.validateRoleId(reason, qry.roleId());

        return reason;
      }

      ReasonsGroupType operator()(const interface::GetAssetInfo &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetAssetInfo";

        validator_.validateAssetId(reason, qry.assetId());

        return reason;
      }

      ReasonsGroupType operator()(
          const interface::GetPendingTransactions &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetPendingTransactions";
        if (qry.paginationMeta()) {
          // TODO igor-egorov 2019-06-06 IR-516 Make meta non-optional
          validator_.validateTxPaginationMeta(reason, *qry.paginationMeta());
        }

        return reason;
      }

      ReasonsGroupType operator()(const interface::GetPeers &qry) const {
        ReasonsGroupType reason;
        reason.first = "GetPeers";

        return reason;
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
       * @return Answer containing found error if any
       */
      Answer validate(const interface::Query &qry) const override {
        Answer answer;
        std::string qry_reason_name = "Query";
        ReasonsGroupType qry_reason(qry_reason_name, GroupedReasons());

        field_validator_.validateCreatorAccountId(qry_reason,
                                                  qry.creatorAccountId());
        field_validator_.validateCreatedTime(qry_reason, qry.createdTime());
        field_validator_.validateCounter(qry_reason, qry.queryCounter());

        if (not qry_reason.second.empty()) {
          answer.addReason(std::move(qry_reason));
        }

        auto field_reason =
            boost::apply_visitor(query_field_validator_, qry.get());
        if (not field_reason.second.empty()) {
          answer.addReason(std::move(field_reason));
        }

        return answer;
      }

     protected:
      Answer answer_;
      FieldValidator field_validator_;
      QueryFieldValidator query_field_validator_;
    };
  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_QUERY_VALIDATOR_HPP
