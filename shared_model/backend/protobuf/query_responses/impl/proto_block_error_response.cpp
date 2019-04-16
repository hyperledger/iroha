/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_error_response.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    BlockErrorResponse::BlockErrorResponse(QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          block_error_response{proto_->block_error_response()},
          message_{block_error_response.message()} {}

    template BlockErrorResponse::BlockErrorResponse(
        BlockErrorResponse::TransportType &);
    template BlockErrorResponse::BlockErrorResponse(
        const BlockErrorResponse::TransportType &);
    template BlockErrorResponse::BlockErrorResponse(
        BlockErrorResponse::TransportType &&);

    BlockErrorResponse::BlockErrorResponse(const BlockErrorResponse &o)
        : BlockErrorResponse(o.proto_) {}

    BlockErrorResponse::BlockErrorResponse(BlockErrorResponse &&o)
        : BlockErrorResponse(std::move(o.proto_)) {}

    const interface::types::DescriptionType &BlockErrorResponse::message()
        const {
      return message_;
    }

  }  // namespace proto
}  // namespace shared_model
