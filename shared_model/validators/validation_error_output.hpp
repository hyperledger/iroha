/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_VALIDATION_ERROR_OUTPUT_HPP
#define IROHA_VALIDATION_ERROR_OUTPUT_HPP

#include "validators/validation_error.hpp"

#include <iosfwd>
#include <optional>

namespace shared_model {
  namespace validation {

    // Puts toString() to the stream. Useful for GTest checks.
    std::ostream &operator<<(std::ostream &os, const ValidationError &o);

  }  // namespace validation
}  // namespace shared_model

std::ostream &operator<<(
    std::ostream &out,
    const std::optional<shared_model::validation::ValidationError> &error);

#endif
