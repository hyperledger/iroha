/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SET_HPP
#define IROHA_SET_HPP

#include <unordered_set>

namespace iroha {
  /**
       * Merge collections with unique elements
       * @tparam Collection - type of collection
       * @tparam TargetType - type of elements in collection
       * @tparam Hasher - class for hashing TargetType objects
       * @param left - first collection
       * @param right - second collection
       * @return collection with type Collection, that contain unique union of elements
       */
  template<typename Hasher,
      typename Collection,
      typename TargetType = typename Collection::value_type>
  auto merge_unique(Collection left, Collection right) {
    std::unordered_set<TargetType, Hasher>
        unique_set(left.begin(), left.end());

    unique_set.insert(right.begin(), right.end());
    return Collection(unique_set.begin(), unique_set.end());
  }

  /**
   * Provide merge of sets based on mering same elements
   * @tparam Set - type of set
   * @tparam Merge - type of merge predicate
   * @param left - first set
   * @param right - second set
   * @param merge - merge predicate
   * @return new set, that contains union of elements,
   * where same elements merged inside
   */
  template<typename Set, typename Merge>
  Set set_union(const Set &left, const Set &right, Merge &&merge) {
    Set out;
    out.insert(left.begin(), left.end());
    for (auto &&tx : right) {
      auto iter = out.find(tx);
      if (iter != out.end()) {
        merge(*iter, tx);
      } else {
        out.insert(tx);
      }
    }
    return out;
  }

  /**
   * Provide difference operation on set
   * @tparam Set - type of set
   * @return difference of sets.
   */
  template<typename Set>
  Set set_difference(const Set &left, const Set &right) {
    Set out;
    for (auto &&element : left) {
      if (right.find(element) == right.end()) {
        out.insert(element);
      }
    }
    return out;
  }
} // namespace iroha
#endif //IROHA_SET_HPP
