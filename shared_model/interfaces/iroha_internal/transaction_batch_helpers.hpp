/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_BATCH_HELPERS_HPP
#define IROHA_TRANSACTION_BATCH_HELPERS_HPP

#include <cstring>
#include <sstream>

#include "cryptography/blob.hpp"
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
       * @param number of reduced hashes
       * @return concatenated reduced hashes
       */
      template <typename Collection>
      static types::HashType calculateReducedBatchHash(
          const Collection &reduced_hashes, size_t number) {
        shared_model::crypto::Blob::Bytes concatenated;
        auto it = reduced_hashes.begin();
        const auto end = reduced_hashes.end();
        auto *hash = &*it;
        auto hash_size = hash->blob().size();
        concatenated.reserve(hash_size * number);
        while (true) {
          concatenated.resize(concatenated.size() + hash_size);
          auto *dest = concatenated.data() + concatenated.size() - hash_size;
          std::memcpy(dest, hash->blob().data(), hash_size);
          if (++it == end) {
            break;
          }
          hash = &*it;
          hash_size = hash->blob().size();
        }
        return types::HashType{std::make_shared<shared_model::crypto::Blob>(
            std::move(concatenated))};
      }
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_BATCH_HELPERS_HPP
