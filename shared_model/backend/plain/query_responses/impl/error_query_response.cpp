/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/query_responses/error_query_response.hpp"

using shared_model::plain::ErrorQueryResponse;

namespace {

  const auto get_specific_response_constref =
      [](const auto &specific_response_ptr)
      -> ErrorQueryResponse::QueryErrorResponseVariantType {
    return ErrorQueryResponse::QueryErrorResponseVariantType{
        *specific_response_ptr};
  };

}  // namespace

ErrorQueryResponse::ErrorQueryResponse(
    VariantHolder specific_error_holder,
    shared_model::interface::ErrorQueryResponse::ErrorMessageType error_msg,
    shared_model::interface::ErrorQueryResponse::ErrorCodeType error_code)
    : specific_error_holder_(std::move(specific_error_holder)),
      specific_error_constref_(boost::apply_visitor(
          get_specific_response_constref, specific_error_holder_)),
      error_msg_(std::move(error_msg)),
      error_code_(error_code) {}

const ErrorQueryResponse::QueryErrorResponseVariantType &
ErrorQueryResponse::get() const {
  return specific_error_constref_;
}

const ErrorQueryResponse::ErrorMessageType &ErrorQueryResponse::errorMessage()
    const {
  return error_msg_;
}

ErrorQueryResponse::ErrorCodeType ErrorQueryResponse::errorCode() const {
  return error_code_;
}
