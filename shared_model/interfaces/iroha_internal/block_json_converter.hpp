/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_JSON_CONVERTER_HPP
#define IROHA_BLOCK_JSON_CONVERTER_HPP

#include "interfaces/iroha_internal/block_json_deserializer.hpp"
#include "interfaces/iroha_internal/block_json_serializer.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Block json converter is a class which can convert blocks to/from json
     */
    class BlockJsonConverter : public BlockJsonSerializer,
                               public BlockJsonDeserializer {
     public:
      ~BlockJsonConverter() override = default;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_BLOCK_JSON_CONVERTER_HPP
