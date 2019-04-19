/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_K_TIMES_RECONNECTION_STRATEGY_HPP
#define IROHA_K_TIMES_RECONNECTION_STRATEGY_HPP

#include "ametsuchi/reconnection/reconnection_strategy.hpp"

#include <atomic>

#include "tbb/concurrent_hash_map.h"

namespace iroha {
  namespace ametsuchi {

    /**
     * Class provides implementation of reconnection strategy based on number of
     * attempts.
     *
     * Note: all methods are thread-safe
     */
    class KTimesReconnectionStorageStrategy
        : public ReconnectionStorageStrategy {
     public:
      /**
       * @param number_of_recalls - number of failure attempts before
       * reconnection
       */
      KTimesReconnectionStorageStrategy(size_t number_of_attempts);

      bool canInvoke(const Tag &) override;

      void reset(const Tag &) override;

      Tag makeTag(const Tag &prefix) override;

     private:
      /// shortcut for tag collection type
      using CollectionType =
          tbb::concurrent_hash_map<ReconnectionStorageStrategy::Tag, size_t>;
      CollectionType invokes_;
      size_t number_of_recalls_;

      /// counter for making uniqueness tags
      std::atomic<uint64_t> tag_counter{0u};
    };
  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_K_TIMES_RECONNECTION_STRATEGY_HPP
