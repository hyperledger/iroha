/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_BLOCK_JSON_CONVERTER_HPP
#define IROHA_PROTO_BLOCK_JSON_CONVERTER_HPP

#include "interfaces/common_objects/types.hpp"
#include "interfaces/iroha_internal/block_json_converter.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }

  namespace proto {
    class ProtoBlockJsonConverter : public interface::BlockJsonConverter {
     public:
      iroha::expected::Result<interface::types::JsonType, std::string>
      serialize(const interface::Block &block) const noexcept override;

      iroha::expected::Result<std::unique_ptr<interface::Block>, std::string>
      deserialize(const interface::types::JsonType &json) const
          noexcept override;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_BLOCK_JSON_CONVERTER_HPP
