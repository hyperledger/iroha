/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATOR_MOCKS_HPP
#define IROHA_VALIDATOR_MOCKS_HPP

#include "validators/abstract_validator.hpp"

#include <gmock/gmock.h>
#include "validators/validators_common.hpp"

namespace shared_model {
  namespace validation {

    // TODO: kamilsa 01.02.2018 IR-873 Replace all these validators with mock
    // classes

    struct AlwaysValidValidator {
      AlwaysValidValidator(std::shared_ptr<ValidatorsConfig>) {}

      template <typename T>
      std::optional<ValidationError> validate(const T &) const {
        return std::nullopt;
      }
    };

    template <typename T>
    class MockValidator : public AbstractValidator<T> {
     public:
      MockValidator() = default;
      MockValidator(std::shared_ptr<ValidatorsConfig>){};
      MOCK_CONST_METHOD1_T(validate, std::optional<ValidationError>(const T &));
    };

  }  // namespace validation
}  // namespace shared_model

#endif  // IROHA_VALIDATOR_MOCKS_HPP
