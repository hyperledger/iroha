/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATION_ERROR_HELPERS_HPP
#define IROHA_VALIDATION_ERROR_HELPERS_HPP

#include <optional>
#include "validators/validation_error.hpp"

namespace shared_model {
  namespace validation {

    /// Helper class for ValidationError creation.
    class ValidationErrorCreator {
     public:
      /**
       * Extract the error, if any.
       * @param name - the name of resulting error, if any.
       */
      std::optional<ValidationError> getValidationError(
          const ReasonName &name) &&;

      /**
       * Extract the error, if any.
       * @param name_provider - a callable providing the name of resulting
       * error, if any.
       */
      template <typename NameProvider>
      std::optional<ValidationError> getValidationErrorWithGeneratedName(
          NameProvider &&name_provider) && {
        if (optional_error_) {
          optional_error_->name = std::forward<NameProvider>(name_provider)();
        }
        return std::move(optional_error_);
      }

      /// Add a reason to error.
      ValidationErrorCreator &addReason(ReasonType reason);

      /// Add a child error.
      ValidationErrorCreator &addChildError(ValidationError error);

      /// Add a reason, if any.
      ValidationErrorCreator &operator|=(
          std::optional<ReasonType> optional_reason);

      /// Add a child error, if any.
      ValidationErrorCreator &operator|=(
          std::optional<ValidationError> optional_error);

     private:
      ValidationError &getOrCreateValidationError();

      std::optional<ValidationError> optional_error_;
    };

    std::optional<ValidationError> operator|(
        std::optional<ValidationError> oe1, std::optional<ValidationError> oe2);

    /**
     * Create an error if provided some reasons or child errors.
     * @param name - resulting error name.
     * @param optional_reasons - a collection of optional error reasons
     * @param optional_child_errors - optional child errors
     * @return an error with all present reasons and child errors from
     * parameters, if any, or std::nullopt, if not any reason nor error
     * provided.
     */
    std::optional<ValidationError> aggregateErrors(
        const ReasonName &name,
        std::vector<std::optional<ReasonType>> optional_reasons,
        std::vector<std::optional<ValidationError>> optional_child_errors);

  }  // namespace validation
}  // namespace shared_model

#endif
