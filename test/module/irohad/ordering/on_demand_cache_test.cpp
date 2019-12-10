/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/ordering_gate_cache/on_demand_cache.hpp"

#include <gtest/gtest.h>

#include "cryptography/blob.hpp"
#include "module/shared_model/interface_mocks.hpp"

using namespace iroha::ordering::cache;
using ::testing::ByMove;
using ::testing::ElementsAre;
using ::testing::IsEmpty;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::UnorderedElementsAre;

/**
 * @given empty cache
 * @when add to back is invoked with batch1 and batch2
 * @then back of the cache consists has batch1 and batch2
 */
TEST(OnDemandCacheTest, TestAddToBack) {
  OnDemandCache cache;

  shared_model::interface::types::HashType hash1(
      shared_model::crypto::Blob::fromBinaryString("hash1"));
  auto batch1 = createMockBatchWithHash(hash1);

  shared_model::interface::types::HashType hash2(
      shared_model::crypto::Blob::fromBinaryString("hash2"));
  auto batch2 = createMockBatchWithHash(hash2);

  cache.addToBack({batch1, batch2});

  ASSERT_THAT(cache.tail(), UnorderedElementsAre(batch1, batch2));
}

/**
 * @given cache with batch1 in the head, batch2 in the middle and batch3 in the
 * tail
 * @when pop is invoked 4 times
 * @then first three times batch1, batch2 and batch3 will be returned
 * correspondingly and no batch will be returned 4th time
 */
TEST(OnDemandCache, Pop) {
  OnDemandCache cache;

  shared_model::interface::types::HashType hash1(
      shared_model::crypto::Blob::fromBinaryString("hash1"));
  shared_model::interface::types::HashType hash2(
      shared_model::crypto::Blob::fromBinaryString("hash2"));
  shared_model::interface::types::HashType hash3(
      shared_model::crypto::Blob::fromBinaryString("hash3"));

  auto batch1 = createMockBatchWithHash(hash1);
  auto batch2 = createMockBatchWithHash(hash2);
  auto batch3 = createMockBatchWithHash(hash3);

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
TEST(OnDemandCache, Remove) {
  OnDemandCache cache;

  shared_model::interface::types::HashType hash1(
      shared_model::crypto::Blob::fromBinaryString("hash1"));
  shared_model::interface::types::HashType hash2(
      shared_model::crypto::Blob::fromBinaryString("hash2"));
  shared_model::interface::types::HashType hash3(
      shared_model::crypto::Blob::fromBinaryString("hash3"));

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
  ASSERT_THAT(cache.head(), UnorderedElementsAre(batch1, batch2));

  cache.remove({hash1});
  /**
   * 1. {batch2}
   * 2.
   * 3.
   */
  ASSERT_THAT(cache.head(), ElementsAre(batch2));
}
