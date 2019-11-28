/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP

#include "interfaces/query_responses/error_query_response.hpp"

#include <memory>

#include "common/result_fwd.hpp"

namespace iroha {
  namespace protocol {
    class ErrorResponse;
    class QueryResponse;
  }  // namespace protocol
}  // namespace iroha

namespace shared_model {
  namespace proto {
    class ErrorQueryResponse final : public interface::ErrorQueryResponse {
     public:
      static iroha::expected::Result<std::unique_ptr<ErrorQueryResponse>,
                                     std::string>
      create(const iroha::protocol::QueryResponse &query_response);

      ErrorQueryResponse(const iroha::protocol::QueryResponse &query_response,
                         shared_model::interface::QueryErrorType error_reason);

      ErrorQueryResponse(ErrorQueryResponse &&o) noexcept;

      ~ErrorQueryResponse() override;

      shared_model::interface::QueryErrorType reason() const override;

      const ErrorMessageType &errorMessage() const override;

      ErrorCodeType errorCode() const override;

     private:
      const iroha::protocol::ErrorResponse &error_response_;
      shared_model::interface::QueryErrorType error_reason_;
      const ErrorMessageType &error_message_;
      ErrorCodeType error_code_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
