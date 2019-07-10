/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP

#include "interfaces/query_responses/error_query_response.hpp"

#include "backend/protobuf/query_responses/proto_concrete_error_query_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class ErrorQueryResponse final : public interface::ErrorQueryResponse {
     public:
      /// type of proto variant
      using ProtoQueryErrorResponseVariantType =
          boost::variant<StatelessFailedErrorResponse,
                         StatefulFailedErrorResponse,
                         NoAccountErrorResponse,
                         NoAccountAssetsErrorResponse,
                         NoAccountDetailErrorResponse,
                         NoSignatoriesErrorResponse,
                         NotSupportedErrorResponse,
                         NoAssetErrorResponse,
                         NoRolesErrorResponse>;

      /// list of types in proto variant
      using ProtoQueryErrorResponseListType =
          ProtoQueryErrorResponseVariantType::types;

      explicit ErrorQueryResponse(
          iroha::protocol::QueryResponse &query_response);

      const QueryErrorResponseVariantType &get() const override;

      const ErrorMessageType &errorMessage() const override;

      ErrorCodeType errorCode() const override;

     private:
      iroha::protocol::ErrorResponse &error_response_;

      ProtoQueryErrorResponseVariantType variant_;

      QueryErrorResponseVariantType ivariant_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
