/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_response.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    BlockResponse::BlockResponse(QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          block_response_{proto_->block_response()},
          block_{block_response_.block().block_v1()} {}

    template BlockResponse::BlockResponse(BlockResponse::TransportType &);
    template BlockResponse::BlockResponse(const BlockResponse::TransportType &);
    template BlockResponse::BlockResponse(BlockResponse::TransportType &&);

    BlockResponse::BlockResponse(const BlockResponse &o)
        : BlockResponse(o.proto_) {}

    BlockResponse::BlockResponse(BlockResponse &&o) noexcept
        : BlockResponse(std::move(o.proto_)) {}

    const Block &BlockResponse::block() const {
      return block_;
    }

  }  // namespace proto
}  // namespace shared_model
