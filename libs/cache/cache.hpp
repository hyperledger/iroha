/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CACHE_HPP
#define IROHA_CACHE_HPP

#include "cache/abstract_cache.hpp"

#include <unordered_map>

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
              size_t Count = 20000ull>
    class Cache final
        : public AbstractCache<KeyType,
                               ValueType,
                               Cache<KeyType, ValueType, KeyHash, Count>> {
      using HashType =
          decltype(std::declval<KeyHash>()(std::declval<KeyType>()));

      struct KeyAndValue {
        HashType hash;
        ValueType value;

        KeyAndValue() = delete;
        KeyAndValue(KeyAndValue const &) = delete;
        KeyAndValue(HashType h, ValueType const &v) : hash(h), value(v) {}

        KeyAndValue &operator=(KeyAndValue const &) = delete;
      };

      using ValuesBuffer = containers::RingBuffer<KeyAndValue, Count>;
      using ValueHandle = typename ValuesBuffer::Handle;
      using KeyValuesBuffer = std::unordered_map<HashType, ValueHandle>;

      inline HashType toHash(KeyType const &key) const {
        return KeyHash()(key);
      }

     public:
      Cache() {}

      uint32_t getIndexSizeHighImpl() const {
        return Count;
      }

      uint32_t getCacheItemCountImpl() const {
        return static_cast<uint32_t>(keys_.size());
      }

      void addItemImpl(const KeyType &key, const ValueType &value) {
        auto const hash = toHash(key);
        auto it = keys_.find(hash);
        if (keys_.end() == it) {
          values_.push(
              [&](ValueHandle h, KeyAndValue const & /*value*/) {
                this->keys_[hash] = h;
              },
              [&](ValueHandle h, KeyAndValue const &stored_value) {
                BOOST_ASSERT_MSG(
                    this->keys_.end() != this->keys_.find(stored_value.hash),
                    "keys_ must contain item, which we want to remove!");
                this->keys_.erase(stored_value.hash);
              },
              hash,
              value);
        } else {
          auto &stored_value = values_.getItem(it->second);
          stored_value.value = value;
        }
      }

      boost::optional<ValueType> findItemImpl(const KeyType &key) const {
        auto const hash = toHash(key);
        auto it = keys_.find(hash);

        if (keys_.end() == it) {
          return boost::none;
        } else {
          return values_.getItem(it->second).value;
        }
      }

     private:
      KeyValuesBuffer keys_;
      ValuesBuffer values_;
    };
  }  // namespace cache
}  // namespace iroha

#endif  // IROHA_CACHE_HPP
