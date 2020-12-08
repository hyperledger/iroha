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
      std::optional<ValidationError> validateAccountId(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAssetId(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateBytecode(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateEvmHexAddress(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validatePeer(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAmount(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validatePubkey(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validatePeerAddress(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateRoleId(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAccountName(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateDomainId(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateDomain(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAssetName(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAccountDetailKey(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAccountDetailValue(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validatePrecision(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateRolePermission(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateGrantablePermission(
          Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateQuorum(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateCreatorAccountId(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAccount(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateCreatedTime(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateCounter(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateSignatureForm(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateSignatures(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateQueryPayloadMeta(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateDescription(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateBatchMeta(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateHeight(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateHash(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateTxPaginationMeta(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAccountAsset(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAsset(Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAccountDetailRecordId(
          Args...) const {
        return std::nullopt;
      }
      template <typename... Args>
      std::optional<ValidationError> validateAccountDetailPaginationMeta(
          Args...) const {
        return std::nullopt;
      }
    };

    template <typename Model>
    struct AlwaysValidModelValidator final : public AbstractValidator<Model> {
     public:
      std::optional<ValidationError> validate(const Model &m) const override {
        return std::nullopt;
      };
    };

  }  // namespace validation
}  // namespace shared_model

#endif /* IROHA_ALWAYS_VALID_VALIDATORS_HPP_ */
