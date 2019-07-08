/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_BLOCK_ERROR_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_BLOCK_ERROR_RESPONSE_HPP

#include "interfaces/query_responses/block_error_response.hpp"

#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class BlockErrorResponse final : public interface::BlockErrorResponse {
     public:
      explicit BlockErrorResponse(
          iroha::protocol::BlockQueryResponse &block_query_response);

      const interface::types::DescriptionType &message() const override;

     private:
      const iroha::protocol::BlockErrorResponse &block_error_response;

      const interface::types::DescriptionType message_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_BLOCK_ERROR_RESPONSE_HPP
