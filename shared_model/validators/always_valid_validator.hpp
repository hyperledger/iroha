/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ALWAYS_VALID_VALIDATOR_HPP
#define IROHA_ALWAYS_VALID_VALIDATOR_HPP

#include "validators/abstract_validator.hpp"

namespace shared_model {
  namespace validation {
    template <typename T>
    class AlwaysValidValidator
        : public shared_model::validation::AbstractValidator<T> {
     public:
      AlwaysValidValidator() = default;
      AlwaysValidValidator(
          std::shared_ptr<shared_model::validation::ValidatorsConfig>){};
      boost::optional<ValidationError> validate(const T &m) const override {
        return boost::none;
      }
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_ALWAYS_VALID_VALIDATOR_HPP
