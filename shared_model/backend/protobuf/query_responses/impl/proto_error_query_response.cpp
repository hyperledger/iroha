/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_error_query_response.hpp"
#include "utils/variant_deserializer.hpp"

namespace shared_model {
  namespace proto {

    ErrorQueryResponse::ErrorQueryResponse(
        iroha::protocol::QueryResponse &query_response)
        : error_response_(*query_response.mutable_error_response()),
          variant_{[this] {
            auto &ar = error_response_;

            unsigned which = ar.GetDescriptor()
                                 ->FindFieldByName("reason")
                                 ->enum_type()
                                 ->FindValueByNumber(ar.reason())
                                 ->index();
            return shared_model::detail::
                variant_impl<ProtoQueryErrorResponseListType>::template load<
                    ProtoQueryErrorResponseVariantType>(ar, which);
          }()},
          ivariant_{QueryErrorResponseVariantType{variant_}} {}

    const ErrorQueryResponse::QueryErrorResponseVariantType &
    ErrorQueryResponse::get() const {
      return ivariant_;
    }

    const ErrorQueryResponse::ErrorMessageType &
    ErrorQueryResponse::errorMessage() const {
      return error_response_.message();
    }

    ErrorQueryResponse::ErrorCodeType ErrorQueryResponse::errorCode() const {
      return error_response_.error_code();
    }

  }  // namespace proto
}  // namespace shared_model
