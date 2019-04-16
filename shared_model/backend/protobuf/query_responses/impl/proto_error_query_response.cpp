/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_error_query_response.hpp"
#include "utils/variant_deserializer.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    ErrorQueryResponse::ErrorQueryResponse(QueryResponseType &&response)
        : CopyableProto(std::forward<QueryResponseType>(response)),
          variant_{[this] {
            auto &&ar = proto_->error_response();

            unsigned which = ar.GetDescriptor()
                                 ->FindFieldByName("reason")
                                 ->enum_type()
                                 ->FindValueByNumber(ar.reason())
                                 ->index();
            return shared_model::detail::
                variant_impl<ProtoQueryErrorResponseListType>::template load<
                    ProtoQueryErrorResponseVariantType>(
                    std::forward<decltype(ar)>(ar), which);
          }()},
          ivariant_{QueryErrorResponseVariantType{variant_}} {}

    template ErrorQueryResponse::ErrorQueryResponse(
        ErrorQueryResponse::TransportType &);
    template ErrorQueryResponse::ErrorQueryResponse(
        const ErrorQueryResponse::TransportType &);
    template ErrorQueryResponse::ErrorQueryResponse(
        ErrorQueryResponse::TransportType &&);

    ErrorQueryResponse::ErrorQueryResponse(const ErrorQueryResponse &o)
        : ErrorQueryResponse(o.proto_) {}

    ErrorQueryResponse::ErrorQueryResponse(ErrorQueryResponse &&o) noexcept
        : ErrorQueryResponse(std::move(o.proto_)) {}

    const ErrorQueryResponse::QueryErrorResponseVariantType &
    ErrorQueryResponse::get() const {
      return ivariant_;
    }

    const ErrorQueryResponse::ErrorMessageType &
    ErrorQueryResponse::errorMessage() const {
      return proto_->error_response().message();
    }

    ErrorQueryResponse::ErrorCodeType ErrorQueryResponse::errorCode() const {
      return proto_->error_response().error_code();
    }

  }  // namespace proto
}  // namespace shared_model
