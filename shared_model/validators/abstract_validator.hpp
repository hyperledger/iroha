/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ABSTRACT_VALIDATOR_HPP
#define IROHA_ABSTRACT_VALIDATOR_HPP

#include <optional>
#include "validators/validation_error.hpp"

namespace shared_model {
  namespace validation {

    // validator which can be overloaded for dynamic polymorphism
    template <typename Model>
    class AbstractValidator {
     public:
      virtual std::optional<ValidationError> validate(const Model &m) const = 0;

      virtual ~AbstractValidator() = default;
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_ABSTRACT_VALIDATOR_HPP
