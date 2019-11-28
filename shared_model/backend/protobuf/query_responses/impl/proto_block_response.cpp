/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_block_response.hpp"

#include "backend/protobuf/block.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    iroha::expected::Result<std::unique_ptr<BlockResponse>, std::string>
    BlockResponse::create(
        const iroha::protocol::BlockResponse &query_response) {
      return Block::create(query_response.block().block_v1()) |
          [&](auto &&block) {
            return std::make_unique<BlockResponse>(std::move(block));
          };
    }

    BlockResponse::BlockResponse(
        std::unique_ptr<shared_model::interface::Block> block)
        : block_{std::move(block)} {}

    BlockResponse::~BlockResponse() = default;

    const interface::Block &BlockResponse::block() const {
      return *block_;
    }

  }  // namespace proto
}  // namespace shared_model
