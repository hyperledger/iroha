/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ALWAYS_VALID_VALIDATORS_HPP_
#define IROHA_ALWAYS_VALID_VALIDATORS_HPP_

#include "validators/abstract_validator.hpp"

/* These classes are supposed to be used in testing cases, where we need to
 * create objects bypassing any validation, so purportedly invalid data can be
 * made.
 */

namespace shared_model {
  namespace validation {

    struct AlwaysValidFieldValidator final {
      AlwaysValidFieldValidator(std::shared_ptr<ValidatorsConfig>) {}

      template <typename... Args>
      boost::optional<ValidationError> validateAccountId(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAssetId(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validatePeer(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAmount(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validatePubkey(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validatePeerAddress(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateRoleId(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAccountName(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateDomainId(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateDomain(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAssetName(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAccountDetailKey(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAccountDetailValue(
          Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validatePrecision(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateRolePermission(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateGrantablePermission(
          Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateQuorum(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateCreatorAccountId(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAccount(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateCreatedTime(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateCounter(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateSignatureForm(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateSignatures(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateQueryPayloadMeta(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateDescription(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateBatchMeta(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateHeight(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateHash(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateTxPaginationMeta(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAccountAsset(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAsset(Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAccountDetailRecordId(
          Args...) const {
        return boost::none;
      }
      template <typename... Args>
      boost::optional<ValidationError> validateAccountDetailPaginationMeta(
          Args...) const {
        return boost::none;
      }
    };

    template <typename Model>
    struct AlwaysValidModelValidator final : public AbstractValidator<Model> {
     public:
      boost::optional<ValidationError> validate(const Model &m) const override {
        return boost::none;
      };
    };

  }  // namespace validation
}  // namespace shared_model

#endif /* IROHA_ALWAYS_VALID_VALIDATORS_HPP_ */
