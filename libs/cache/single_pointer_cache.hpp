/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SINGLE_POINTER_CACHE_HPP
#define IROHA_SINGLE_POINTER_CACHE_HPP

#include <memory>
#include <mutex>

namespace iroha::cache {

  /**
   * Thread-safely stores and returns shared pointer to an element of template
   * type
   */
  template <typename DataType>
  struct SinglePointerCache final {
    /**
     * Pointer to data type
     */
    using DataPointer = std::shared_ptr<std::decay_t<DataType>>;

    /**
     * Insert data to the cache
     * @param pointer to the data to be inserted
     */
    void insert(DataPointer data) {
      stored_data_ = std::move(data);
    }

    /**
     * Get data from the cache
     * @return pointer to the stored data
     */
    DataPointer get() const {
      return stored_data_;
    }

    /**
     * Delete data inside the cache
     */
    void release() {
      stored_data_.reset();
    }

   private:
    DataPointer stored_data_;
  };

}  // namespace iroha::cache

#endif  // IROHA_SINGLE_POINTER_CACHE_HPP
