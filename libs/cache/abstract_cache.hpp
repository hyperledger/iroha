/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ABSTRACT_CACHE_HPP
#define IROHA_ABSTRACT_CACHE_HPP

#include <boost/optional.hpp>
#include <list>
#include <shared_mutex>
#include <string>

namespace iroha {
  namespace cache {
    /**
     * Cache for any key-value types.
     * Internally it uses a map to cache ItemTypes and linked list
     * based index of KeyTypes to remove oldest items when getIndexSizeHigh() is
     * reached. Implemented as a CRTP pattern.
     * @tparam KeyType - type of cache keys
     * @tparam ValueType - type of cache values
     * @tparam T - type of implementation
     */
    template <typename KeyType, typename ValueType, typename T>
    class AbstractCache {
     public:
      /**
       * @return high border of cache limit (@see AbstractCache#addItem)
       */
      uint32_t getIndexSizeHigh() const {
        // shared lock
        std::shared_lock<std::shared_timed_mutex> lock(access_mutex_);
        return constUnderlying().getIndexSizeHighImpl();
      }

      /**
       * @return amount of items in cache
       */
      uint32_t getCacheItemCount() const {
        // shared lock
        std::shared_lock<std::shared_timed_mutex> lock(access_mutex_);
        return constUnderlying().getCacheItemCountImpl();
      }

      /**
       * Adds new item to cache. When amount of cache records reaches
       * getIndexSizeHigh() a procedure of clean starts until getIndexSizeLow()
       * records left. Note: cache does not have a remove method, deletion
       * performs automatically.
       * Since every add operation can potentially lead to deletion,
       * it should be protected by mutex.
       * @param key - key to insert
       * @param value - value to insert
       */
      void addItem(const KeyType &key, const ValueType &value) {
        // exclusive lock
        std::lock_guard<std::shared_timed_mutex> lock(access_mutex_);
        underlying().addItemImpl(key, value);
      }

      /**
       * Performs a search for an item with a specific key.
       * @param hash - key to find
       * @return Optional of ValueType
       */
      boost::optional<ValueType> findItem(const KeyType &key) const {
        std::shared_lock<std::shared_timed_mutex> lock(access_mutex_);
        return constUnderlying().findItemImpl(key);
      }

     private:
      const T &constUnderlying() const {
        return static_cast<const T &>(*this);
      }
      T &underlying() {
        return static_cast<T &>(*this);
      }

      mutable std::shared_timed_mutex access_mutex_;
    };
  }  // namespace cache
}  // namespace iroha

#endif  // IROHA_ABSTRACT_CACHE_HPP
