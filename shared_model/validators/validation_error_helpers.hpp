/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATION_ERROR_HELPERS_HPP
#define IROHA_VALIDATION_ERROR_HELPERS_HPP

#include <boost/optional/optional.hpp>
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
      boost::optional<ValidationError> getValidationError(
          const ReasonName &name) &&;

      /**
       * Extract the error, if any.
       * @param name_provider - a callable providing the name of resulting
       * error, if any.
       */
      template <typename NameProvider>
      boost::optional<ValidationError> getValidationErrorWithGeneratedName(
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
          boost::optional<ReasonType> optional_reason);

      /// Add a child error, if any.
      ValidationErrorCreator &operator|=(
          boost::optional<ValidationError> optional_error);

     private:
      ValidationError &getOrCreateValidationError();

      boost::optional<ValidationError> optional_error_;
    };

    boost::optional<ValidationError> operator|(
        boost::optional<ValidationError> oe1,
        boost::optional<ValidationError> oe2);

    /**
     * Create an error if provided some reasons or child errors.
     * @param name - resulting error name.
     * @param optional_reasons - a collection of optional error reasons
     * @param optional_child_errors - optional child errors
     * @return an error with all present reasons and child errors from
     * parameters, if any, or boost::none, if not any reason nor error provided.
     */
    boost::optional<ValidationError> aggregateErrors(
        const ReasonName &name,
        std::vector<boost::optional<ReasonType>> optional_reasons,
        std::vector<boost::optional<ValidationError>> optional_child_errors);

  }  // namespace validation
}  // namespace shared_model

#endif
