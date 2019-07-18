/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_JSON_SERIALIZER_HPP
#define IROHA_BLOCK_JSON_SERIALIZER_HPP

#include <memory>

#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Block;
    /**
     * BlockJsonSerializer is an interface which allows transforming block
     * objects to json
     */
    class BlockJsonSerializer {
     public:
      /**
       * Try to transform block to json string
       * @param block - block to be serialized
       * @return json string or an error
       */
      virtual iroha::expected::Result<types::JsonType, std::string> serialize(
          const Block &block) const = 0;

      virtual ~BlockJsonSerializer() = default;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_BLOCK_JSON_SERIALIZER_HPP
