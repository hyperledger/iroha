/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_get_block_response.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    GetBlockResponse::GetBlockResponse(QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          block_response_{proto_->block_response()},
          block_{block_response_.block().block_v1()} {}

    template GetBlockResponse::GetBlockResponse(
        GetBlockResponse::TransportType &);
    template GetBlockResponse::GetBlockResponse(
        const GetBlockResponse::TransportType &);
    template GetBlockResponse::GetBlockResponse(
        GetBlockResponse::TransportType &&);

    GetBlockResponse::GetBlockResponse(const GetBlockResponse &o)
        : GetBlockResponse(o.proto_) {}

    GetBlockResponse::GetBlockResponse(GetBlockResponse &&o)
        : GetBlockResponse(std::move(o.proto_)) {}

    const interface::Block &GetBlockResponse::block() const {
      return block_;
    }

  }  // namespace proto
}  // namespace shared_model
