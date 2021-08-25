/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_error_query_response.hpp"

#include <boost/variant/variant.hpp>
#include "backend/protobuf/query_responses/proto_concrete_error_query_response.hpp"
#include "common/report_abort.h"

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
}  // namespace

#ifdef IROHA_BIND_TYPE
#error IROHA_BIND_TYPE defined.
#endif  // IROHA_BIND_TYPE
#define IROHA_BIND_TYPE(val, type, ...)        \
  case iroha::protocol::ErrorResponse::val:    \
    return ProtoQueryErrorResponseVariantType( \
        shared_model::proto::type(__VA_ARGS__))

namespace shared_model::proto {

  struct ErrorQueryResponse::Impl {
    explicit Impl(iroha::protocol::QueryResponse &ref)
        : error_response_{*ref.mutable_error_response()},
          variant_{[this] {
            auto &ar = error_response_;

            switch (ar.reason()) {
              IROHA_BIND_TYPE(
                  STATELESS_INVALID, StatelessFailedErrorResponse, ar);
              IROHA_BIND_TYPE(
                  STATEFUL_INVALID, StatefulFailedErrorResponse, ar);
              IROHA_BIND_TYPE(NO_ACCOUNT, NoAccountErrorResponse, ar);
              IROHA_BIND_TYPE(
                  NO_ACCOUNT_ASSETS, NoAccountAssetsErrorResponse, ar);
              IROHA_BIND_TYPE(
                  NO_ACCOUNT_DETAIL, NoAccountDetailErrorResponse, ar);
              IROHA_BIND_TYPE(NO_SIGNATORIES, NoSignatoriesErrorResponse, ar);
              IROHA_BIND_TYPE(NOT_SUPPORTED, NotSupportedErrorResponse, ar);
              IROHA_BIND_TYPE(NO_ASSET, NoAssetErrorResponse, ar);
              IROHA_BIND_TYPE(NO_ROLES, NoRolesErrorResponse, ar);

              default:
                report_abort("Unexpected query error response case.");
            }
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

  const ErrorQueryResponse::ErrorMessageType &ErrorQueryResponse::errorMessage()
      const {
    return impl_->error_response_.message();
  }

  ErrorQueryResponse::ErrorCodeType ErrorQueryResponse::errorCode() const {
    return impl_->error_response_.error_code();
  }

}  // namespace shared_model::proto

#undef IROHA_BIND_TYPE
