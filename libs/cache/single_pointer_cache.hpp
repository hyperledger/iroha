/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SINGLE_POINTER_CACHE_HPP
#define IROHA_SINGLE_POINTER_CACHE_HPP

#include <memory>
#include <mutex>

#include "common/common.hpp"

namespace iroha::cache {

  /**
     * Thread-safely stores and returns shared pointer to an element of template
     * type
   */
  template <typename DataType>
  class SinglePointerCache {
   public:
    /**
       * Pointer to data type
     */
    using DataPointer = std::shared_ptr<std::decay_t<DataType>>;
    using DataSet = std::vector<DataPointer>;

    /**
       * Insert data to the cache
       * @param pointer to the data to be inserted
     */
    void insert(DataPointer data) {
      stored_data_.template exclusiveAccess(
          [data{std::move(data)}](auto &data_set) mutable {
            data_set.emplace_back(std::move(data));
          });
    }

    /**
       * Get data from the cache
       * @return pointer to the stored data
     */
    template <typename F>
    void get(F &&f) const {
      stored_data_.template sharedAccess(std::forward<F>(f));
    }

    /**
       * Delete data inside the cache
     */
    void release() {
      stored_data_.template exclusiveAccess(
          [](auto &data_set) { data_set.clear(); });
    }

   private:
    utils::ReadWriteObject<DataSet> stored_data_;
  };

}  // namespace iroha::cache

#endif  // IROHA_SINGLE_POINTER_CACHE_HPP
