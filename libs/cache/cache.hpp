/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CACHE_HPP
#define IROHA_CACHE_HPP

#include "cache/abstract_cache.hpp"

#include <unordered_map>

#include "ametsuchi/impl/in_memory_storage.hpp"
#include "common/ring_buffer.hpp"

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
              typename KeyHash = std::hash<KeyType>,
              size_t Count = 2000ull>
    class Cache final
        : public AbstractCache<KeyType,
                               ValueType,
                               Cache<KeyType, ValueType, KeyHash, Count>> {
      using HashType =
          decltype(std::declval<KeyHash>()(std::declval<KeyType>()));

      using InternalStorage =
          ametsuchi::InMemoryFrame<HashType, ValueType, Count>;
      InternalStorage internal_storage_;

      inline HashType toHash(KeyType const &key) const {
        return KeyHash()(key);
      }

     public:
      Cache() {}

      uint32_t getIndexSizeHighImpl() const {
        return Count;
      }

      uint32_t getCacheItemCountImpl() const {
        return internal_storage_.size();
      }

      void addItemImpl(const KeyType &key, const ValueType &value) {
        internal_storage_.template insert(toHash(key), value);
      }

      boost::optional<ValueType> findItemImpl(const KeyType &key) const {
        if (auto res = internal_storage_.find(toHash(key)))
          return res.value().get();

        return boost::none;
      }
    };
  }  // namespace cache
}  // namespace iroha

#endif  // IROHA_CACHE_HPP
