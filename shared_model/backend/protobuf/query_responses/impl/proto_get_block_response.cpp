/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_get_block_response.hpp"

namespace shared_model {
  namespace proto {

    GetBlockResponse::GetBlockResponse(
        iroha::protocol::QueryResponse &query_response)
        : block_response_{query_response.block_response()},
          block_{*query_response.mutable_block_response()
                      ->mutable_block()
                      ->mutable_block_v1()} {}

    const interface::Block &GetBlockResponse::block() const {
      return block_;
    }

  }  // namespace proto
}  // namespace shared_model
