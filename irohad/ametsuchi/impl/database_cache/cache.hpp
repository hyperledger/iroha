/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef AMETSUCHI_DATABASE_CACHE_HPP
#define AMETSUCHI_DATABASE_CACHE_HPP

#include <algorithm>
#include <deque>
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

    /// Layer that represents database.
    std::unique_ptr<iroha::RadixTree<Type>> db_representation_cache_;

    /// Layers that represents:
    /// intermediate_cache_[0] - current transaction
    /// intermediate_cache_[X] - savepoints, where X > 0.
    /// Should be merged from X = N to X = 0.
    /// std::optional represents that value can be deleted.
    /// Uses stack representation of layers.
    std::deque<std::unique_ptr<iroha::RadixTree<std::optional<Type>>>>
        intermediate_cache_;

    auto cachebleSearch(std::string_view key) const {
      auto it = std::lower_bound(
          cacheable_paths_.begin(), cacheable_paths_.end(), key);
      return it != cacheable_paths_.begin() ? --it : it;
    }

    void checkStates() {
      assert(db_representation_cache_);
      assert(!intermediate_cache_.empty());
      for (auto const &ic : intermediate_cache_) {
        assert(ic);
      }
    }

    void pushLayer() {
      intermediate_cache_.emplace_back(
          std::make_unique<iroha::RadixTree<std::optional<Type>>>());
    }

    /// Remove last layer except first one.
    void popLayer() {
      if (intermediate_cache_.size() > 1)
        intermediate_cache_.pop_back();
    }

    void dropIntermediateCache() {
      intermediate_cache_.clear();
      pushLayer();
    }

    void mergeMove(std::unique_ptr<iroha::RadixTree<std::optional<Type>>> &from,
                   std::unique_ptr<iroha::RadixTree<std::optional<Type>>> &to) {
      from->filterEnumerate(
          nullptr, 0ul, [&](std::string_view key, std::optional<Type> *value) {
            to->template insert(key.data(), key.size(), std::move(*value));
          });
    }

   public:
    DatabaseCache(DatabaseCache const &) = delete;
    DatabaseCache &operator=(DatabaseCache const &) = delete;

    DatabaseCache() {
      drop();
    }

    static bool allowed(std::string_view const &key) {
      for (auto c : key)
        if (!Alphabet::allowed(c))
          return false;
      return true;
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
      /// Check state correctness.
      checkStates();

      /// Search in intermediate layers at first
      for (auto it = intermediate_cache_.rbegin();
           it != intermediate_cache_.rend();
           ++it)
        if (auto *ptr = (*it)->find(key.data(), key.size()))
          return *ptr ? std::forward<Func>(func)(**ptr) : false;

      /// If not found, we look at DB representation.
      if (auto *ptr = db_representation_cache_->find(key.data(), key.size()))
        return std::forward<Func>(func)(*ptr);

      /// Nothing found.
      return false;
    }

    void set(std::string_view key, std::string_view const &value) {
      /// Check state correctness.
      checkStates();
      assert(isCacheable(key));

      /// insert to the last layer.
      intermediate_cache_.back()->template insert(
          key.data(), key.size(), value);
    }

    void setCommit(std::string_view key, std::string_view const &value) {
      /// Check state correctness.
      checkStates();
      assert(isCacheable(key));
      for (auto &c : intermediate_cache_) {
        assert(c->find(key.data(), key.size()) == nullptr);
      }

      /// Since this data is present in database, we store it directly in
      /// database representation.
      db_representation_cache_->template insert(key.data(), key.size(), value);
    }

    auto erase(std::string_view key) {
      /// Check state correctness.
      checkStates();
      assert(isCacheable(key));

      /// Insert erase state in last layer.
      return intermediate_cache_.back()->template insert(
          key.data(), key.size(), std::nullopt);
    }

    void filterDelete(std::string_view filter) {
      /// Check state correctness.
      checkStates();

      /// Mark values that are present in all caches deleted.
      db_representation_cache_->filterEnumerate(
          filter.data(), filter.size(), [&](std::string_view key, Type *) {
            intermediate_cache_.back()->template insert(
                key.data(), key.size(), std::nullopt);
          });

      if (intermediate_cache_.size() > 1)
        for (size_t ix = 0; ix < intermediate_cache_.size() - 1ull; ++ix)
          intermediate_cache_[ix]->filterEnumerate(
              filter.data(),
              filter.size(),
              [&](std::string_view key, std::optional<Type> *) {
                intermediate_cache_.back()->template insert(
                    key.data(), key.size(), std::nullopt);
              });

      intermediate_cache_.back()->filterEnumerate(
          filter.data(),
          filter.size(),
          [&](std::string_view key, std::optional<Type> *value) {
            assert(value);
            *value = std::nullopt;
          });
    }

    void savepoint() {
      pushLayer();
    }

    void releaseSavepoint() {
      if (intermediate_cache_.size() <= 1)
        return;

      auto &from = intermediate_cache_.back();
      auto &to = *(intermediate_cache_.rbegin() + 1ull);

      mergeMove(from, to);
      popLayer();
    }

    void rollbackToSavepoint() {
      popLayer();
    }

    void rollback() {
      /// Check state correctness.
      checkStates();

      /// Drop all transactions data
      dropIntermediateCache();
    }

    void commit() {
      /// Check state correctness.
      checkStates();

      /// Commits all data from intermediate layers to DB representation
      for (auto &it : intermediate_cache_)
        it->filterEnumerate(
            nullptr,
            0ul,
            [&](std::string_view key, std::optional<Type> *value) {
              if (*value)
                db_representation_cache_->template insert(
                    key.data(), key.size(), std::move(**value));
              else
                db_representation_cache_->erase(key.data(), key.size());
            });

      /// Remove all intermediate state
      dropIntermediateCache();
    }

    void drop() {
      /// Clear DB representation.
      db_representation_cache_ = std::make_unique<iroha::RadixTree<Type>>();

      /// Clear intermediate layers.
      dropIntermediateCache();

      /// Check state correctness.
      checkStates();
    }
  };

}  // namespace iroha::ametsuchi

#endif  // AMETSUCHI_DATABASE_CACHE_HPP
