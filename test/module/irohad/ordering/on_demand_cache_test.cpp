/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/ordering_gate_cache/on_demand_cache.hpp"

#include <gtest/gtest.h>

#include "module/shared_model/interface_mocks.hpp"

using namespace iroha::ordering::cache;
using ::testing::ByMove;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::UnorderedElementsAre;

const uint64_t kMaxCacheSize = 10000;

class OnDemandCacheTest : public ::testing::Test {
 public:
  OnDemandCacheTest() : cache(kMaxCacheSize) {}
  OnDemandCache cache;
};

/**
 * @given empty cache
 * @when add to back is invoked with batch1 and batch2
 * @then back of the cache consists has batch1 and batch2
 */
TEST_F(OnDemandCacheTest, TestAddToBack) {
  shared_model::interface::types::HashType hash1("hash1");
  auto tx1 = createMockTransactionWithHash(hash1);
  auto batch1 = createMockBatchWithTransactions({tx1}, "batch1");

  shared_model::interface::types::HashType hash2("hash2");
  auto tx2 = createMockTransactionWithHash(hash2);
  auto batch2 = createMockBatchWithTransactions({tx2}, "batch2");

  cache.addToBack({batch1, batch2});

  ASSERT_THAT(cache.back(), UnorderedElementsAre(batch1, batch2));
}

/**
 * @given cache with batch1 in the head, batch2 in the middle and batch3 in the
 * tail
 * @when pop is invoked 4 times
 * @then first three times batch1, batch2 and batch3 will be returned
 * correspondingly and no batch will be returned 4th time
 */
TEST_F(OnDemandCacheTest, Pop) {
  shared_model::interface::types::HashType hash1("hash1");
  shared_model::interface::types::HashType hash2("hash2");
  shared_model::interface::types::HashType hash3("hash3");
  auto tx1 = createMockTransactionWithHash(hash1);
  auto tx2 = createMockTransactionWithHash(hash2);
  auto tx3 = createMockTransactionWithHash(hash3);

  auto batch1 = createMockBatchWithTransactions({tx1}, "batch1");
  auto batch2 = createMockBatchWithTransactions({tx2}, "batch2");
  auto batch3 = createMockBatchWithTransactions({tx3}, "batch3");

  cache.addToBack({batch1});
  /**
   * 1. {} <- will be popped
   * 2. {}
   * 3. {batch1}
   */
  ASSERT_THAT(cache.pop(), IsEmpty());

  cache.addToBack({batch2});
  /**
   * 1. {} <- will be popped
   * 2. {batch1}
   * 3. {batch2}
   */
  ASSERT_THAT(cache.pop(), IsEmpty());

  cache.addToBack({batch3});

  /**
   * 1. {batch1} <- will be popped
   * 2. {batch2}
   * 3. {batch3}
   */
  ASSERT_THAT(cache.pop(), ElementsAre(batch1));

  /**
   * 1. {batch2} <- will be popped
   * 2. {batch3}
   * 3. {}
   */
  ASSERT_THAT(cache.pop(), ElementsAre(batch2));

  /**
   * 1. {batch3} <- will be popped
   * 2. {}
   * 3. {}
   */
  ASSERT_THAT(cache.pop(), ElementsAre(batch3));

  /**
   * 1. {} <- will be popped
   * 2. {}
   * 3. {}
   */
  ASSERT_THAT(cache.pop(), IsEmpty());
}

/**
 * @given cache with batch1 and batch2 on the top
 * @when remove({hash1}) is invoked, where hash1 is the hash of transactions
 * from batch1
 * @then only batch2 remains on the head of the queue
 */
TEST_F(OnDemandCacheTest, Remove) {
  shared_model::interface::types::HashType hash1("hash1");
  shared_model::interface::types::HashType hash2("hash2");
  shared_model::interface::types::HashType hash3("hash3");

  auto tx1 = createMockTransactionWithHash(hash1);
  auto tx2 = createMockTransactionWithHash(hash2);
  auto tx3 = createMockTransactionWithHash(hash3);

  auto batch1 = createMockBatchWithTransactions({tx1, tx2}, "abc");
  auto batch2 = createMockBatchWithTransactions({tx3}, "123");

  cache.addToBack({batch1, batch2});
  cache.pop();
  cache.pop();
  /**
   * 1. {batch1, batch2}
   * 2.
   * 3.
   */
  ASSERT_THAT(cache.front(), UnorderedElementsAre(batch1, batch2));

  cache.remove({hash1});
  /**
   * 1. {batch2}
   * 2.
   * 3.
   */
  ASSERT_THAT(cache.front(), ElementsAre(batch2));
}

/**
 * @given a cache with maximum size 3 and all the 3 elements are inside
 * @when an element is removed from the cache
 * @then only one element is possible to add to the cache
 */
TEST_F(OnDemandCacheTest, InternalStateCorrectness) {
  OnDemandCache cache(3);
  shared_model::interface::types::HashType hash1("hash1");
  shared_model::interface::types::HashType hash2("hash2");
  shared_model::interface::types::HashType hash3("hash3");
  shared_model::interface::types::HashType hash4("hash4");
  shared_model::interface::types::HashType hash5("hash5");

  auto tx1 = createMockTransactionWithHash(hash1);
  auto tx2 = createMockTransactionWithHash(hash2);
  auto tx3 = createMockTransactionWithHash(hash3);
  auto tx4 = createMockTransactionWithHash(hash4);
  auto tx5 = createMockTransactionWithHash(hash5);

  auto batch1 = createMockBatchWithTransactions({tx1}, "first");
  auto batch2 = createMockBatchWithTransactions({tx2}, "second");
  auto batch3 = createMockBatchWithTransactions({tx3}, "third");
  auto batch4 = createMockBatchWithTransactions({tx4}, "fourth");
  auto batch5 = createMockBatchWithTransactions({tx5}, "fifth");

  ASSERT_TRUE(cache.addToBack({batch1, batch2, batch3}));
  cache.remove({hash1});
  ASSERT_TRUE(cache.addToBack({batch4}));
  ASSERT_FALSE(cache.addToBack({batch5}));
}
