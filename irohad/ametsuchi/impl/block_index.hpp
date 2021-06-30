/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_INDEX_HPP
#define IROHA_BLOCK_INDEX_HPP

#include <memory>
#include <common/result_fwd.hpp>

namespace shared_model {
  namespace interface {
    class Block;
  }  // namespace interface
}  // namespace shared_model

namespace iroha::ametsuchi {
    /**
     * Internal interface for modifying index on blocks and transactions
     */
    class BlockIndex {
     public:
      virtual ~BlockIndex() = default;

      /**
       * Create necessary indexes for block
       * @param block to be indexed
       */
      virtual void index(const shared_model::interface::Block &,
                         bool do_flush = true) = 0;

      virtual iroha::expected::Result<void, std::string> flush() = 0;
    };
}  // namespace iroha::ametsuchi

#endif  // IROHA_BLOCK_INDEX_HPP
