/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COLLECTION_SET_HPP
#define IROHA_COLLECTION_SET_HPP

#include <shared_mutex>
#include <unordered_set>

namespace iroha {
  namespace set {

    /**
     * Class provides concurrent implementation of collection which operates
     * with collections on insert and remove
     *
     * @tparam Key - type of holding values
     * @tparam Hash - hash representation of Key values
     * @tparam KeyEqual - equality type
     */
    template <typename Key,
              typename Hash = std::hash<Key>,
              typename KeyEqual = std::equal_to<Key>>
    class CollectionSet {
     public:
      CollectionSet() = default;

      using value_type = Key;

      /**
       * Merge our and passed collection
       * @tparam Collection - type of passed collection
       * @param collection - elements to insert
       */
      template <typename Collection>
      void insertValues(Collection &&collection) {
        std::lock_guard<std::shared_timed_mutex> lock(mutex_);
        set_.insert(collection.begin(), collection.end());
      }

      /**
       * Remove all elements which are occured in the passed collection
       * @tparam Collection - type of passed collection
       * @param collection - elements to remove
       */
      template <typename Collection>
      void removeValues(Collection &&collection) {
        std::lock_guard<std::shared_timed_mutex> lock(mutex_);
        for (auto &&val : collection) {
          set_.erase(val);
        }
      }

      /**
       * Blocking walk through the collection
       * @tparam Callable - type of functor
       * @param callable - functor for invocation on each element
       */
      template <typename Callable>
      void forEach(Callable &&callable) const {
        std::shared_lock<std::shared_timed_mutex> lock(mutex_);
        std::for_each(set_.begin(), set_.end(), callable);
      }

     private:
      std::unordered_set<Key, Hash, KeyEqual> set_;
      mutable std::shared_timed_mutex mutex_;
    };
  }  // namespace set
}  // namespace iroha

#endif  // IROHA_COLLECTION_SET_HPP
