/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "validators/validation_error_helpers.hpp"

#include <ciso646>

#include <boost/range/numeric.hpp>
#include "utils/string_builder.hpp"

using namespace shared_model::validation;

std::optional<ValidationError> ValidationErrorCreator::getValidationError(
    const ReasonName &name) && {
  if (optional_error_) {
    optional_error_->name = name;
  }
  return std::move(optional_error_);
}

ValidationErrorCreator &ValidationErrorCreator::addReason(ReasonType reason) {
  getOrCreateValidationError().my_errors.emplace_back(std::move(reason));
  return *this;
}

ValidationErrorCreator &ValidationErrorCreator::addChildError(
    ValidationError error) {
  getOrCreateValidationError().child_errors.emplace_back(std::move(error));
  return *this;
}

ValidationErrorCreator &ValidationErrorCreator::operator|=(
    std::optional<ReasonType> optional_reason) {
  if (optional_reason) {
    return addReason(std::move(optional_reason).value());
  }
  return *this;
}

ValidationErrorCreator &ValidationErrorCreator::operator|=(
    std::optional<ValidationError> optional_error) {
  if (optional_error) {
    return addChildError(std::move(optional_error).value());
  }
  return *this;
}

ValidationError &ValidationErrorCreator::getOrCreateValidationError() {
  if (not optional_error_) {
    optional_error_ = ValidationError({}, {});
  }
  return optional_error_.value();
}

std::optional<ValidationError> shared_model::validation::aggregateErrors(
    const ReasonName &name,
    std::vector<std::optional<ReasonType>> optional_reasons,
    std::vector<std::optional<ValidationError>> optional_child_errors) {
  ValidationErrorCreator error_creator;
  for (auto &optional_reason : optional_reasons) {
    error_creator |= std::move(optional_reason);
  }
  for (auto &optional_error : optional_child_errors) {
    error_creator |= std::move(optional_error);
  }
  return std::move(error_creator).getValidationError(name);
}

std::optional<ValidationError> operator|(std::optional<ValidationError> oe1,
                                         std::optional<ValidationError> oe2) {
  if (oe1) {
    if (oe2) {
      return oe1.value() |= std::move(oe2).value();
    }
    return oe1;
  }
  return oe2;
}
