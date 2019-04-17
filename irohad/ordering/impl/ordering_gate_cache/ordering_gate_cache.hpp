/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_ORDERING_CACHE_HPP
#define IROHA_ON_DEMAND_ORDERING_CACHE_HPP

#include <unordered_set>

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace interface {
    class TransactionBatch;
  }
}  // namespace shared_model

namespace iroha {
  namespace ordering {
    namespace cache {

      /**
       * Cache for transactions sent to ordering gate
       */
      class OrderingGateCache {
       private:
        /**
         * Hasher for the shared pointer on the batch. Uses batch's reduced hash
         */
        struct BatchPointerHasher {
          shared_model::crypto::Hash::Hasher hasher_;

          size_t operator()(
              const std::shared_ptr<shared_model::interface::TransactionBatch>
                  &a) const;
        };

       public:
        /// type of the element in cache container. Set is used as it allows to
        /// remove batch from BatchSet with O(1) complexity, which is the case
        /// in remove method
        using BatchesSetType = std::unordered_set<
            std::shared_ptr<shared_model::interface::TransactionBatch>,
            BatchPointerHasher>;

        using HashesSetType =
            std::unordered_set<shared_model::crypto::Hash,
                               shared_model::crypto::Hash::Hasher>;

        /**
         * Concatenates batches from the tail of the queue with provided batches
         * @param batches - input batches
         * @return bool - true if batches were stored in cache
         */
        virtual bool addToBack(const BatchesSetType &batches) = 0;

        /**
         * Pops the head batches and returns them
         */
        virtual BatchesSetType pop() = 0;

        /**
         * Removes batches by provided hashes from the head of the queue
         */
        virtual void remove(const HashesSetType &hashes) = 0;

        /**
         * Return the head batches
         */
        virtual const BatchesSetType &front() const = 0;

        /**
         * Return the tail batches
         */
        virtual const BatchesSetType &back() const = 0;

        /**
         * Puts the head batches to back. The second set of batches will be a
         * head.
         */
        virtual void rotate() = 0;

        virtual ~OrderingGateCache() = default;
      };

    }  // namespace cache

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_ORDERING_CACHE_HPP
