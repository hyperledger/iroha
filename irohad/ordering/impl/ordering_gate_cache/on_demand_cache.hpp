/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_CACHE_HPP
#define IROHA_ON_DEMAND_CACHE_HPP

#include "ordering/impl/ordering_gate_cache/ordering_gate_cache.hpp"

#include <shared_mutex>

#include <boost/circular_buffer.hpp>

namespace iroha {
  namespace ordering {
    namespace cache {

      class OnDemandCache : public OrderingGateCache {
       public:
        /**
         * Create OnDemandCache instance
         * @param max_cache_size - maximum amount of transactions contained in
         * cache (calculated as a sum over all stored batches)
         */
        OnDemandCache(uint64_t max_cache_size);

        bool addToBack(const BatchesSetType &batches) override;

        BatchesSetType pop() override;

        void remove(const HashesSetType &hashes) override;

        virtual const BatchesSetType &front() const override;

        virtual const BatchesSetType &back() const override;

        virtual void rotate() override;

        size_t availableTxsCapacity() const override;

       private:
        const uint64_t max_cache_size_;
        mutable std::shared_timed_mutex mutex_;
        using CacheElementType =
            std::pair<uint64_t /* a number of transactions over all elements
                                  from the second part of that pair */
                      ,
                      BatchesSetType>;
        using BatchesQueueType = boost::circular_buffer<CacheElementType>;
        BatchesQueueType circ_buffer{3, CacheElementType{}};
      };

    }  // namespace cache
  }    // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_CACHE_HPP
