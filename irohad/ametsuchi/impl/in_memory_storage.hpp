/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_IN_MEMORY_FRAME_HPP
#define IROHA_IN_MEMORY_FRAME_HPP

#include <memory>
#include <optional>
#include <unordered_map>
#include <utility>

#include "common/common.hpp"
#include "common/ring_buffer.hpp"

namespace iroha::ametsuchi {

  /**
   * Cache based on ring buffer with hash-table index for
   * fast search.It has limited size and will overwrite the most irrelevant
   * value on store operation when fully loaded.
   */
  template <typename KeyT, typename ValueT, size_t kCount>
  class InMemoryFrame final : utils::NoCopy, utils::NoMove {
   public:
    using KeyType = KeyT;
    using ValueType = ValueT;
    static constexpr size_t ItemsCount = kCount;

   private:
    using Entry = std::pair<KeyType, ValueType>;
    using ValuesBuffer = containers::RingBuffer<Entry, ItemsCount>;
    using ValueHandle = typename ValuesBuffer::Handle;

    containers::RingBuffer<Entry, ItemsCount> data_;
    std::unordered_map<KeyT, ValueHandle> index_;
    size_t all_time_values_;

   public:
    InMemoryFrame() : all_time_values_(0ull) {}

    template <typename K, typename V>
    void insert(K &&key, V &&value) {
      if (auto it = index_.find(std::forward<K>(key)); index_.end() == it)
        data_.push(
            [&](ValueHandle h, Entry const & /*value*/) {
              index_[std::forward<K>(key)] = h;
              ++all_time_values_;
            },
            [&](ValueHandle h, Entry const &stored_value) {
              assert(index_.end() != index_.find(stored_value.first));
              index_.erase(stored_value.first);
            },
            std::forward<K>(key),
            std::forward<V>(value));
      else
        data_.getItem(it->second).second = std::forward<V>(value);
    }

    std::optional<std::reference_wrapper<ValueType const>> find(
        KeyType const &key) const {
      if (auto it = index_.find(key); index_.end() == it)
        return std::nullopt;
      else
        return data_.getItem(it->second).second;
    }

    void clear() {
      while (!data_.empty())
        data_.template pop(
            [](ValueHandle /*h*/, Entry const & /*stored_value*/) {});
      index_.clear();
    }

    template <typename FuncT>
    void forEach(FuncT &&func) const {
      data_.template foreach (
          [func(std::forward<FuncT>(func))](ValueHandle /*h*/,
                                            Entry const &value) mutable {
            func(value.first, value.second);
            return true;
          });
    }

    size_t size() const {
      return index_.size();
    }

    size_t allTimeValues() const {
      return all_time_values_;
    }
  };

}  // namespace iroha::ametsuchi

#endif  // IROHA_IN_MEMORY_FRAME_HPP
