/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_error_response.hpp"

namespace shared_model {
  namespace proto {

    BlockErrorResponse::BlockErrorResponse(
        iroha::protocol::BlockQueryResponse &block_query_response)
        : block_error_response{block_query_response.block_error_response()},
          message_{block_error_response.message()} {}

    const interface::types::DescriptionType &BlockErrorResponse::message()
        const {
      return message_;
    }

  }  // namespace proto
}  // namespace shared_model
