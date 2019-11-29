/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/raw_block_loader.hpp"

#include <fstream>

#include "backend/protobuf/block.hpp"
#include "common/bind.hpp"
#include "common/result.hpp"
#include "converters/protobuf/json_proto_converter.hpp"

namespace iroha {
  namespace main {

    using shared_model::converters::protobuf::jsonToProto;
    using shared_model::interface::Block;

    iroha::expected::Result<std::unique_ptr<Block>, std::string>
    BlockLoader::parseBlock(const std::string &data) {
      return jsonToProto<iroha::protocol::Block>(data) | [](auto &&block)
                 -> std::unique_ptr<shared_model::interface::Block> {
        return std::make_unique<shared_model::proto::Block>(
            std::move(block.block_v1()));
      };
    }
  }  // namespace main
}  // namespace iroha
