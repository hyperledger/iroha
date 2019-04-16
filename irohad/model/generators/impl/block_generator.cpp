/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/generators/block_generator.hpp"

#include "model/sha3_hash.hpp"

namespace iroha {
  namespace model {
    namespace generators {
      Block BlockGenerator::generateGenesisBlock(
          ts64_t created_ts, const std::vector<Transaction> &transactions) {
        Block block{};
        block.created_ts = created_ts;
        block.height = 1;
        std::fill(block.prev_hash.begin(), block.prev_hash.end(), 0);
        block.txs_number = 1;
        block.transactions = transactions;
        block.hash = hash(block);

        return block;
      }

    }  // namespace generators
  }    // namespace model
}  // namespace iroha
