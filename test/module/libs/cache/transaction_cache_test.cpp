/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include <vector>

#include "cache/collection_set.hpp"

using namespace iroha::set;

class TransactionCacheTest : public testing::Test {
 public:
  uint32_t number_of_calls = 0;
  std::shared_ptr<CollectionSet<int>> set;

  void SetUp() override {
    number_of_calls = 0;
    set = std::make_shared<CollectionSet<int>>();
  }
};

/**
 * @given empty set
 * @when  check that empty set doesn't contain elements
 * AND insert some collection
 * @then  check that elements are appeared
 */
TEST_F(TransactionCacheTest, insert) {
  set->forEach([this](const auto &val) { number_of_calls++; });
  ASSERT_EQ(0, number_of_calls);

  set->insertValues(std::vector<int>({1, 2}));

  set->forEach([this](const auto &val) { number_of_calls++; });
  ASSERT_EQ(2, number_of_calls);
}

/**
 * @given empty set
 * @when insert some collection
 * AND insert duplicated elements
 * @then  check that duplicates are not appeared
 */
TEST_F(TransactionCacheTest, insertDuplicates) {
  set->insertValues(std::vector<int>({1, 2}));
  set->insertValues(std::vector<int>({1, 3}));

  set->forEach([this](const auto &val) { number_of_calls++; });
  ASSERT_EQ(3, number_of_calls);
}

/**
 * @given empty set
 * @when insert some collection
 * AND remove another collection with same and different elements
 * @then  check that duplicates and removed elements are not appeared
 */
TEST_F(TransactionCacheTest, remove) {
  set->insertValues(std::vector<int>({1, 2, 3}));
  set->removeValues(std::vector<int>({1, 3, 4}));
  set->forEach([this](const auto &val) { number_of_calls++; });
  ASSERT_EQ(1, number_of_calls);
}

/**
 * @given set with existed state
 * @when  insert the set to target collection
 * AND call forEach and push all elements to out set
 * @then  check is first and out sets are the same
 */
TEST_F(TransactionCacheTest, checkElements) {
  std::unordered_set<int> first = {1, 2, 3};
  set->insertValues(first);

  std::unordered_set<int> permutation;
  set->forEach([&permutation](const auto &val) { permutation.insert(val); });
  std::is_permutation(first.begin(), first.end(), permutation.begin());
}
