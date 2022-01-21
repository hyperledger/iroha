/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_DATABASE_CACHE_HPP
#define AMETSUCHI_DATABASE_CACHE_HPP

#include <algorithm>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/common.hpp"
#include "common/radix_tree.hpp"

namespace iroha::ametsuchi {

  template <typename Type>
  class DatabaseCache {
    using CachebleSetType = std::vector<std::string>;

    CachebleSetType cacheable_paths_;
    std::unique_ptr<iroha::RadixTree<Type>> cache_;
    std::unique_ptr<iroha::RadixTree<std::optional<Type>>> tmp_cache_;

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
      if (auto *ptr = tmp_cache_->find(key.data(), key.size()))
        return *ptr ? std::forward<Func>(func)(**ptr) : false;
      if (auto *ptr = cache_->find(key.data(), key.size()))
        return std::forward<Func>(func)(*ptr);
      return false;
    }

    void set(std::string_view key, std::string_view const &value) {
      assert(isCacheable(key));
      tmp_cache_->template insert(key.data(), key.size(), value);
    }

    void setCommit(std::string_view key, std::string_view const &value) {
      assert(isCacheable(key));
      assert(tmp_cache_->find(key.data(), key.size()) == nullptr);
      cache_->template insert(key.data(), key.size(), value);
    }

    auto erase(std::string_view key) {
      return tmp_cache_->template insert(key.data(), key.size(), std::nullopt);
    }

    void filterDelete(std::string_view filter) {
      cache_->filterEnumerate(
          filter.data(), filter.size(), [&](std::string_view key, Type *) {
            tmp_cache_->template insert(key.data(), key.size(), std::nullopt);
          });
    }

    void rollback() {
      tmp_cache_ = std::make_unique<iroha::RadixTree<std::optional<Type>>>();
    }

    void commit() {
      tmp_cache_->filterEnumerate(
          nullptr, 0ul, [&](std::string_view key, std::optional<Type> *value) {
            if (*value)
              cache_->template insert(
                  key.data(), key.size(), std::move(**value));
            else
              cache_->erase(key.data(), key.size());
          });
      tmp_cache_ = std::make_unique<iroha::RadixTree<std::optional<Type>>>();
    }

    void drop() {
      cache_ = std::make_unique<iroha::RadixTree<Type>>();
      tmp_cache_ = std::make_unique<iroha::RadixTree<std::optional<Type>>>();
    }
  };

}  // namespace iroha::ametsuchi

#endif  // AMETSUCHI_DATABASE_CACHE_HPP
