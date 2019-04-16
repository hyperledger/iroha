/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/query_responses/proto_concrete_error_query_response.hpp"
#include "interfaces/query_responses/error_query_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class ErrorQueryResponse final
        : public CopyableProto<interface::ErrorQueryResponse,
                               iroha::protocol::QueryResponse,
                               ErrorQueryResponse> {
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

      template <typename QueryResponseType>
      explicit ErrorQueryResponse(QueryResponseType &&response);

      ErrorQueryResponse(const ErrorQueryResponse &o);

      ErrorQueryResponse(ErrorQueryResponse &&o) noexcept;

      const QueryErrorResponseVariantType &get() const override;

      const ErrorMessageType &errorMessage() const override;

      ErrorCodeType errorCode() const override;

     private:
      const ProtoQueryErrorResponseVariantType variant_;

      const QueryErrorResponseVariantType ivariant_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
