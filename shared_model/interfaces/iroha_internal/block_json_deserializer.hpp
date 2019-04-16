/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_JSON_DESERIALIZER_HPP
#define IROHA_BLOCK_JSON_DESERIALIZER_HPP

#include <memory>

#include "common/result.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    class Block;
    /**
     * BlockJsonDeserializer is an interface which allows transforming json
     * string to block objects.
     */
    class BlockJsonDeserializer {
     public:
      /**
       * Try to parse json string into a block object
       * @param json - json string for a block
       * @return pointer to a block if json was valid or an error
       */
      virtual iroha::expected::Result<std::unique_ptr<Block>, std::string>
      deserialize(const types::JsonType &json) const = 0;

      virtual ~BlockJsonDeserializer() = default;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_BLOCK_JSON_DESERIALIZER_HPP
