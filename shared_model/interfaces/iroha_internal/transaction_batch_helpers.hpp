/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_BATCH_HELPERS_HPP
#define IROHA_TRANSACTION_BATCH_HELPERS_HPP

#include <sstream>

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Provides a method that calculates reduced batch hash
     */
    class TransactionBatchHelpers {
     public:
      /**
       * Get the concatenation of reduced hashes as a single hash
       * That kind of hash does not respect batch type
       * @tparam Collection type of const ref iterator
       * @param reduced_hashes
       * @return concatenated reduced hashes
       */
      template <typename Collection>
      static types::HashType calculateReducedBatchHash(
          const Collection &reduced_hashes) {
        std::stringstream concatenated_hash;
        for (const auto &hash : reduced_hashes) {
          concatenated_hash << hash.hex();
        }
        return types::HashType::fromHexString(concatenated_hash.str());
      }
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_BATCH_HELPERS_HPP
