/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PLAIN_ERROR_RESPONSE_HPP

#include "interfaces/query_responses/error_query_response.hpp"

#include "common/variant_transform.hpp"

namespace shared_model {
  namespace plain {
    class ErrorQueryResponse final : public interface::ErrorQueryResponse {
     public:
      using VariantHolder = iroha::TransformedVariant<
          QueryErrorResponseVariantType,
          iroha::metafunctions::ConstrefToUniquePointer>;

      ErrorQueryResponse(
          VariantHolder specific_error_holder,
          shared_model::interface::ErrorQueryResponse::ErrorMessageType
              error_msg,
          shared_model::interface::ErrorQueryResponse::ErrorCodeType
              error_code);

      const QueryErrorResponseVariantType &get() const override;

      const ErrorMessageType &errorMessage() const override;

      ErrorCodeType errorCode() const override;

     private:
      VariantHolder specific_error_holder_;
      QueryErrorResponseVariantType specific_error_constref_;
      shared_model::interface::ErrorQueryResponse::ErrorMessageType error_msg_;
      shared_model::interface::ErrorQueryResponse::ErrorCodeType error_code_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_ERROR_RESPONSE_HPP
