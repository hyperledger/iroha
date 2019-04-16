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
      void validateAccountId(Args...) const {}
      template <typename... Args>
      void validateAssetId(Args...) const {}
      template <typename... Args>
      void validatePeer(Args...) const {}
      template <typename... Args>
      void validateAmount(Args...) const {}
      template <typename... Args>
      void validatePubkey(Args...) const {}
      template <typename... Args>
      void validatePeerAddress(Args...) const {}
      template <typename... Args>
      void validateRoleId(Args...) const {}
      template <typename... Args>
      void validateAccountName(Args...) const {}
      template <typename... Args>
      void validateDomainId(Args...) const {}
      template <typename... Args>
      void validateAssetName(Args...) const {}
      template <typename... Args>
      void validateAccountDetailKey(Args...) const {}
      template <typename... Args>
      void validateAccountDetailValue(Args...) const {}
      template <typename... Args>
      void validatePrecision(Args...) const {}
      template <typename... Args>
      void validateRolePermission(Args...) const {}
      template <typename... Args>
      void validateGrantablePermission(Args...) const {}
      template <typename... Args>
      void validateQuorum(Args...) const {}
      template <typename... Args>
      void validateCreatorAccountId(Args...) const {}
      template <typename... Args>
      void validateCreatedTime(Args...) const {}
      template <typename... Args>
      void validateCounter(Args...) const {}
      template <typename... Args>
      void validateSignatures(Args...) const {}
      template <typename... Args>
      void validateQueryPayloadMeta(Args...) const {}
      template <typename... Args>
      void validateDescription(Args...) const {}
      template <typename... Args>
      void validateBatchMeta(Args...) const {}
      template <typename... Args>
      void validateHeight(Args...) const {}
      template <typename... Args>
      void validateHash(Args...) const {}
    };

    template <typename Model>
    struct AlwaysValidModelValidator final : public AbstractValidator<Model> {
     public:
      Answer validate(const Model &m) const override {
        return {};
      };
    };

  }  // namespace validation
}  // namespace shared_model

#endif /* IROHA_ALWAYS_VALID_VALIDATORS_HPP_ */
