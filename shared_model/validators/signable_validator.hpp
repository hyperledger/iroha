/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SIGNABLE_VALIDATOR_HPP
#define IROHA_SHARED_MODEL_SIGNABLE_VALIDATOR_HPP

#include "validators/validation_error_helpers.hpp"

namespace shared_model {
  namespace validation {

    template <typename ModelValidator,
              typename Model,
              typename FieldValidator,
              bool SignatureRequired = true>
    class SignableModelValidator : public ModelValidator {
     private:
      template <typename Validator>
      std::optional<ValidationError> validateImpl(const Model &model,
                                                  Validator &&validator) const {
        ValidationErrorCreator error_creator;

        error_creator |= std::forward<Validator>(validator)(model);
        if (SignatureRequired or not model.signatures().empty()) {
          error_creator |= field_validator_.validateSignatures(
              model.signatures(), model.payload());
        }

        return std::move(error_creator).getValidationError("SignedData");
      }

      explicit SignableModelValidator(std::shared_ptr<ValidatorsConfig> config,
                                      FieldValidator &&validator)
          : ModelValidator(config), field_validator_(std::move(validator)) {}

     public:
      explicit SignableModelValidator(std::shared_ptr<ValidatorsConfig> config)
          : SignableModelValidator(config, FieldValidator{config}) {}

      std::optional<ValidationError> validate(
          const Model &model,
          interface::types::TimestampType current_timestamp) const {
        return validateImpl(model, [&, current_timestamp](const Model &m) {
          return ModelValidator::validate(m, current_timestamp);
        });
      }

      std::optional<ValidationError> validate(const Model &model) const {
        return validateImpl(
            model, [&](const Model &m) { return ModelValidator::validate(m); });
      }

     private:
      FieldValidator field_validator_;
    };
  }  // namespace validation
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_SIGNABLE_VALIDATOR_HPP
