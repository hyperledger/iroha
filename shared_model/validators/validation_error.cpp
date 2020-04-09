/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/validation_error.hpp"
#include "validators/validation_error_output.hpp"

#include <cassert>
#include <ciso646>
#include <iostream>

#include "utils/string_builder.hpp"

using namespace shared_model::validation;

ValidationError::ValidationError(ReasonName name,
                                 std::vector<ReasonType> errors,
                                 std::vector<ValidationError> child_errors)
    : name(std::move(name)),
      my_errors(std::move(errors)),
      child_errors(std::move(child_errors)) {}

ValidationError &ValidationError::operator|=(ValidationError other) {
  assert(name == other.name);
  my_errors.reserve(my_errors.size() + other.my_errors.size());
  std::move(other.my_errors.begin(),
            other.my_errors.end(),
            std::back_inserter(my_errors));
  child_errors.reserve(child_errors.size() + other.child_errors.size());
  std::move(other.child_errors.begin(),
            other.child_errors.end(),
            std::back_inserter(child_errors));
  return *this;
}

std::string ValidationError::toString() const {
  auto string_builder = detail::PrettyStringBuilder().init(name);
  if (not my_errors.empty()) {
    string_builder = string_builder.appendNamed("Errors", my_errors);
  }
  if (not child_errors.empty()) {
    string_builder = string_builder.appendNamed("Child errors", child_errors);
  }
  return string_builder.finalize();
}

std::ostream &shared_model::validation::operator<<(std::ostream &os,
                                                   const ValidationError &o) {
  return os << o.toString();
}

std::ostream &operator<<(
    std::ostream &out,
    const std::optional<shared_model::validation::ValidationError> &error) {
  out << error.value();
  return out;
}
