/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_LIMITED_STORAGE_MOVED_ITEM_HPP
#define IROHA_LIBS_LIMITED_STORAGE_MOVED_ITEM_HPP

#include <atomic>
#include <memory>

#include <boost/core/noncopyable.hpp>
#include "storage_shared_limit/storage_limit.hpp"

namespace iroha {

  /// RAII item wrapper for transfers between limited storages
  template <typename Item>
  class MovedItem : public boost::noncopyable {
   public:
    ~MovedItem() {
      if (not is_extracted_.test_and_set()) {
        limit_->remove(item_);
      }
    }

    Item get() const {
      return item_;
    }

    Item extract() {
      if (not is_extracted_.test_and_set()) {
        limit_->remove(item_);
      }
      return item_;
    }

   protected:
    template <typename T>
    friend class LimitedStorage;

    MovedItem(Item item, std::shared_ptr<StorageLimit<Item>> limit)
        : item_(std::move(item)), limit_(std::move(limit)) {}

   private:
    std::atomic_flag is_extracted_ = ATOMIC_FLAG_INIT;
    Item item_;
    std::shared_ptr<StorageLimit<Item>> limit_;
  };

}  // namespace iroha

#endif  // IROHA_LIBS_LIMITED_STORAGE_MOVED_ITEM_HPP
