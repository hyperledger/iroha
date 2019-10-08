/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_error_query_response.hpp"

#include "backend/protobuf/query_responses/proto_concrete_error_query_response.hpp"
#include "utils/variant_deserializer.hpp"

namespace {
  /// type of proto variant
  using ProtoQueryErrorResponseVariantType =
      boost::variant<shared_model::proto::StatelessFailedErrorResponse,
                     shared_model::proto::StatefulFailedErrorResponse,
                     shared_model::proto::NoAccountErrorResponse,
                     shared_model::proto::NoAccountAssetsErrorResponse,
                     shared_model::proto::NoAccountDetailErrorResponse,
                     shared_model::proto::NoSignatoriesErrorResponse,
                     shared_model::proto::NotSupportedErrorResponse,
                     shared_model::proto::NoAssetErrorResponse,
                     shared_model::proto::NoRolesErrorResponse>;

  /// list of types in proto variant
  using ProtoQueryErrorResponseListType =
      ProtoQueryErrorResponseVariantType::types;
}  // namespace

namespace shared_model {
  namespace proto {

    struct ErrorQueryResponse::Impl {
      explicit Impl(iroha::protocol::QueryResponse &ref)
          : error_response_{*ref.mutable_error_response()},
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
            ivariant_{variant_} {}

      iroha::protocol::ErrorResponse &error_response_;

      ProtoQueryErrorResponseVariantType variant_;

      QueryErrorResponseVariantType ivariant_;
    };

    ErrorQueryResponse::ErrorQueryResponse(
        iroha::protocol::QueryResponse &query_response)
        : impl_{std::make_unique<Impl>(query_response)} {}

    ErrorQueryResponse::ErrorQueryResponse(ErrorQueryResponse &&o) noexcept =
        default;

    ErrorQueryResponse::~ErrorQueryResponse() = default;

    const ErrorQueryResponse::QueryErrorResponseVariantType &
    ErrorQueryResponse::get() const {
      return impl_->ivariant_;
    }

    const ErrorQueryResponse::ErrorMessageType &
    ErrorQueryResponse::errorMessage() const {
      return impl_->error_response_.message();
    }

    ErrorQueryResponse::ErrorCodeType ErrorQueryResponse::errorCode() const {
      return impl_->error_response_.error_code();
    }

  }  // namespace proto
}  // namespace shared_model
