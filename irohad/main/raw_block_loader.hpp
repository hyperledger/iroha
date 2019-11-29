/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_RAW_BLOCK_INSERTION_HPP
#define IROHA_RAW_BLOCK_INSERTION_HPP

#include <memory>
#include <string>

#include "common/result_fwd.hpp"

namespace shared_model {
  namespace interface {
    class Block;
  }
}  // namespace shared_model

namespace iroha {
  namespace main {
    /**
     * Class provide functionality to insert blocks to storage
     * without any validation.
     * This class will be useful for creating test environment
     * and testing pipeline.
     */
    class BlockLoader {
     public:
      /**
       * Parse block from JSON string
       * @param data - JSON represenetation of the block
       * @return model Block if operation done successfully, error otherwise
       */
      static iroha::expected::
          Result<std::unique_ptr<shared_model::interface::Block>, std::string>
          parseBlock(const std::string &data);
    };

  }  // namespace main
}  // namespace iroha
#endif  // IROHA_RAW_BLOCK_INSERTION_HPP
