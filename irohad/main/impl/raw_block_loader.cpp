/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/raw_block_loader.hpp"

#include <fstream>

#include "backend/protobuf/block.hpp"
#include "common/bind.hpp"
#include "converters/protobuf/json_proto_converter.hpp"
#include "logger/logger.hpp"

namespace iroha {
  namespace main {

    using shared_model::converters::protobuf::jsonToProto;
    using shared_model::interface::Block;

    BlockLoader::BlockLoader(logger::LoggerPtr log)
        : log_(std::move(log)) {}

    boost::optional<std::shared_ptr<Block>> BlockLoader::parseBlock(
        const std::string &data) {
      return jsonToProto<iroha::protocol::Block>(data) | [](auto &&block) {
        return boost::optional<std::shared_ptr<Block>>(
            std::make_shared<shared_model::proto::Block>(
                std::move(block.block_v1())));
      };
    }

    boost::optional<std::string> BlockLoader::loadFile(
        const std::string &path) {
      std::ifstream file(path);
      if (not file) {
        log_->error("Cannot read '" + path + "'");
        return boost::none;
      }
      std::string str((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
      return str;
    }

  }  // namespace main
}  // namespace iroha
