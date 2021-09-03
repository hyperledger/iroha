/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_DATABASE_CACHE_HPP
#define AMETSUCHI_DATABASE_CACHE_HPP

#include <algorithm>
#include <string>
#include <vector>

#include "common/common.hpp"
#include "common/radix_tree.hpp"

namespace iroha::ametsuchi {

  template <typename Type>
  class DatabaseCache {
    using CachebleSetType = std::vector<std::string>;

    CachebleSetType cacheable_paths_;
    std::unique_ptr<iroha::RadixTree<Type>> cache_;

    auto cachebleSearch(std::string_view key) const {
      auto it = std::lower_bound(
          cacheable_paths_.begin(), cacheable_paths_.end(), key);
      return it != cacheable_paths_.begin() ? --it : it;
    }

   public:
    DatabaseCache(DatabaseCache const &) = delete;
    DatabaseCache &operator=(DatabaseCache const &) = delete;

    DatabaseCache() {
      drop();
    }

    void addCacheblePath(std::string const &path) {
      auto it = cachebleSearch(path);
      auto insert = [&]() {
        cacheable_paths_.emplace_back(path);
        std::sort(cacheable_paths_.begin(), cacheable_paths_.end());
      };

      if (it == cacheable_paths_.end())
        insert();
      else if (it->find(path) == 0ull) {
        cacheable_paths_.erase(it);
        insert();
      } else if (path.find(*it) != 0ull)
        insert();
    }

    bool isCacheable(std::string_view key) const {
      auto it = cachebleSearch(key);
      return (key.find(*it) == 0ull);
    }

    template <typename Func>
    bool get(std::string_view key, Func &&func) {
      if (auto *ptr = cache_->find(key.data(), key.size()))
        return std::forward<Func>(func)(*ptr);
      return false;
    }

    void set(std::string_view key, std::string_view const &value) {
      cache_->template insert(key.data(), key.size(), value);
    }

    auto erase(std::string_view key) {
      return cache_->erase(key.data(), key.size());
    }

    auto filterDelete(std::string_view key) {
      return cache_->filterDelete(key.data(), key.size());
    }

    void drop() {
      cache_ = std::make_unique<iroha::RadixTree<Type>>();
    }
  };

}  // namespace iroha::ametsuchi

#endif  // AMETSUCHI_DATABASE_CACHE_HPP
