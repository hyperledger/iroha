/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_LIBS_LIMITED_STORAGE_HPP
#define IROHA_LIBS_LIMITED_STORAGE_HPP

#include <memory>
#include <type_traits>

#include <boost/core/noncopyable.hpp>
#include "storage_shared_limit/limitable_storage.hpp"
#include "storage_shared_limit/moved_item.hpp"
#include "storage_shared_limit/storage_limit.hpp"

namespace iroha {

  template <class StorageImpl>
  class LimitedStorage : boost::noncopyable {
   public:
    using ItemType = typename StorageImpl::ItemType;
    using LimitType = StorageLimit<ItemType>;
    using MovedItemType = MovedItem<ItemType>;

    static_assert(
        std::is_base_of<LimitableStorage<ItemType>, StorageImpl>::value,
        "The storage implementation must be derived from LimitableStorage!");

    LimitedStorage(std::shared_ptr<LimitType> limit,
                   std::unique_ptr<StorageImpl> storage)
        : limit_(std::move(limit)), storage_(std::move(storage)) {}

    LimitedStorage(LimitedStorage &&other)
        : limit_(std::move(other.limit_)),
          storage_(std::move(other.storage_)),
          items_quantity_(other.items_quantity_) {}

    std::shared_ptr<LimitType> sharedLimit() const {
      return limit_;
    }

    size_t itemsQuantity() const {
      return items_quantity_;
    }

    bool insert(ItemType item) {
      if (not limit_->addIfAllowed(item)) {
        return false;
      }
      updateCountersOnInsertedItem(item);
      return storage_->insert(std::move(item));
    }

    template <typename Lambda>
    auto extract(Lambda extractor) ->
        typename std::result_of<Lambda(StorageImpl &)>::type {
      auto extracted = extractor(*storage_);
      for (const auto &item : extracted) {
        limit_->remove(item);
        updateCountersOnRemovedItem(item);
      }
      return extracted;
    }

    template <typename Lambda>
    auto access(Lambda func) const ->
        typename std::result_of<Lambda(const StorageImpl &)>::type {
      return func(static_cast<const StorageImpl &>(*storage_));
    }

    template <typename Lambda>
    std::vector<std::shared_ptr<MovedItemType>> move(Lambda extractor) {
      auto moved_items = extractor(*storage_);
      std::vector<std::shared_ptr<MovedItemType>> wrapped_moved_items;
      std::transform(moved_items.begin(),
                     moved_items.end(),
                     std::back_inserter(wrapped_moved_items),
                     [this](auto &&moved_item) {
                       this->updateCountersOnRemovedItem(moved_item);
                       return std::shared_ptr<MovedItemType>(
                           new MovedItemType(std::move(moved_item), limit_));
                     });
      return wrapped_moved_items;
    }

    bool insert(std::shared_ptr<MovedItemType> moved) {
      if (moved->limit_ == limit_) {
        moved->is_extracted_.test_and_set();
        return insertUnsafe(moved->item_);
      } else {
        return insert(moved->extract());
      }
    }

   private:
    bool insertUnsafe(ItemType item) {
      updateCountersOnInsertedItem(item);
      return storage_->insert(std::move(item));
    }

    void updateCountersOnInsertedItem(const ItemType &item) {
      ++items_quantity_;
    }

    void updateCountersOnRemovedItem(const ItemType &item) {
      assert(items_quantity_ > 0);
      --items_quantity_;
    }

    std::shared_ptr<LimitType> limit_;
    std::unique_ptr<StorageImpl> storage_;
    size_t items_quantity_{0};
  };

}  // namespace iroha

#endif  // IROHA_LIBS_LIMITED_STORAGE_HPP
