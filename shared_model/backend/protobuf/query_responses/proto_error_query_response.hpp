/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP

#include "interfaces/query_responses/error_query_response.hpp"

#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class ErrorQueryResponse final : public interface::ErrorQueryResponse {
     public:
      explicit ErrorQueryResponse(
          iroha::protocol::QueryResponse &query_response);

      ErrorQueryResponse(ErrorQueryResponse &&o) noexcept;

      ~ErrorQueryResponse() override;

      const QueryErrorResponseVariantType &get() const override;

      const ErrorMessageType &errorMessage() const override;

      ErrorCodeType errorCode() const override;

     private:
      struct Impl;
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ERROR_RESPONSE_HPP
