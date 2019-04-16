/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SINGLE_POINTER_CACHE_HPP
#define IROHA_SINGLE_POINTER_CACHE_HPP

#include <memory>
#include <mutex>

namespace iroha {
  namespace cache {

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

      /**
       * Insert data to the cache
       * @param pointer to the data to be inserted
       */
      void insert(DataPointer data);

      /**
       * Get data from the cache
       * @return pointer to the stored data
       */
      DataPointer get() const;

      /**
       * Delete data inside the cache
       */
      void release();

     private:
      DataPointer stored_data_;

      mutable std::mutex mutex_;
    };

    template <typename DataType>
    void SinglePointerCache<DataType>::insert(
        SinglePointerCache::DataPointer data) {
      std::lock_guard<std::mutex> lock(mutex_);

      stored_data_ = std::move(data);
    }

    template <typename DataType>
    typename SinglePointerCache<DataType>::DataPointer
    SinglePointerCache<DataType>::get() const {
      std::lock_guard<std::mutex> lock(mutex_);

      return stored_data_;
    }

    template <typename DataType>
    void SinglePointerCache<DataType>::release() {
      std::lock_guard<std::mutex> lock(mutex_);

      stored_data_.reset();
    }

  }  // namespace cache
}  // namespace iroha

#endif  // IROHA_SINGLE_POINTER_CACHE_HPP
