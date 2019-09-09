/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CACHE_HPP
#define IROHA_CACHE_HPP

#include "cache/abstract_cache.hpp"

#include <unordered_map>

namespace iroha {
  namespace cache {

    /**
     * Cache for arbitrary types
     * @tparam KeyType type of key objects
     * @tparam ValueType type of value objects
     * @tparam KeyHash hasher for keys
     */
    template <typename KeyType,
              typename ValueType,
              typename KeyHash = std::hash<KeyType>>
    class Cache : public AbstractCache<KeyType,
                                       ValueType,
                                       Cache<KeyType, ValueType, KeyHash>> {
     public:
      Cache(uint32_t max_handler_map_size_high = 20000,
            uint32_t max_handler_map_size_low = 10000)
          : max_handler_map_size_high_(max_handler_map_size_high),
            max_handler_map_size_low_(max_handler_map_size_low) {}

      uint32_t getIndexSizeHighImpl() const {
        return max_handler_map_size_high_;
      }

      uint32_t getIndexSizeLowImpl() const {
        return max_handler_map_size_low_;
      }

      uint32_t getCacheItemCountImpl() const {
        return (uint32_t)handler_map_.size();
      }

      void addItemImpl(const KeyType &key, const ValueType &value) {
        // elements with the same hash should be replaced
        handler_map_[key] = value;
        handler_map_index_.push_back(key);
        if (handler_map_.size() > getIndexSizeHighImpl()) {
          while (handler_map_.size() > getIndexSizeLowImpl()) {
            handler_map_.erase(handler_map_index_.front());
            handler_map_index_.pop_front();
          }
        }
      }

      boost::optional<ValueType> findItemImpl(const KeyType &key) const {
        auto found = handler_map_.find(key);
        if (found == handler_map_.end()) {
          return boost::none;
        } else {
          return found->second;
        }
      }

      // using ValueCreator = std::function<ValueType()>;
      template <typename ValueCreator>
      ValueType getOrCreateImpl(const KeyType &key, ValueCreator creator) {
        auto it = handler_map_.find(key);
        if (it == handler_map_.end()) {
          it = handler_map_.emplace(key, std::move(creator)()).first;
          handler_map_index_.push_back(key);
        }
        return it->second;
      }

     private:
      std::unordered_map<KeyType, ValueType, KeyHash> handler_map_;
      std::list<KeyType> handler_map_index_;

      /**
       * Protection from handler map overflow.
       * TODO 27/10/2017 luckychess Values are quite random and should be tuned
       * for better performance and may be even move to config IR-579
       */
      const uint32_t max_handler_map_size_high_;
      const uint32_t max_handler_map_size_low_;
    };
  }  // namespace cache
}  // namespace iroha

#endif  // IROHA_CACHE_HPP
