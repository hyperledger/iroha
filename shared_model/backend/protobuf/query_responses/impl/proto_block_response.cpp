/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_response.hpp"

namespace shared_model {
  namespace proto {

    BlockResponse::BlockResponse(
        iroha::protocol::BlockQueryResponse &block_query_response)
        : block_response_{block_query_response.block_response()},
          block_{*block_query_response.mutable_block_response()
                      ->mutable_block()
                      ->mutable_block_v1()} {}

    const Block &BlockResponse::block() const {
      return block_;
    }

  }  // namespace proto
}  // namespace shared_model
