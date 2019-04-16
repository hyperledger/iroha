/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "model/block.hpp"
#include "model/generators/transaction_generator.hpp"

#ifndef IROHA_BLOCK_GENERATOR_HPP
#define IROHA_BLOCK_GENERATOR_HPP
namespace iroha {
  namespace model {
    namespace generators {

      class BlockGenerator {
       public:
        /**
         * Generate sample genesis for new Iroha network
         * @param peers_address
         * @param transactions
         * @return model Block
         */
        iroha::model::Block generateGenesisBlock(
            ts64_t created_ts,
            const std::vector<iroha::model::Transaction> &transactions);
      };

    }  // namespace generators
  }    // namespace model
}  // namespace iroha

#endif  // IROHA_BLOCK_GENERATOR_HPP
