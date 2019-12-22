/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATION_ERROR_HPP
#define IROHA_VALIDATION_ERROR_HPP

#include <string>
#include <vector>

namespace shared_model {
  namespace validation {

    using ReasonType = std::string;
    using ReasonName = std::string;

    /// Represents a validation error.
    struct ValidationError {
      ValidationError(ReasonName name,
                      std::vector<ReasonType> errors,
                      std::vector<ValidationError> child_errors = {});

      std::string toString() const;

      /// Merge another validation error into this.
      ValidationError &operator|=(ValidationError other);

      ReasonName name;                            ///< Error reason kind.
      std::vector<ReasonType> my_errors;          ///< Errors of this kind.
      std::vector<ValidationError> child_errors;  ///< Subkind errors.
    };

  }  // namespace validation
}  // namespace shared_model

#endif
