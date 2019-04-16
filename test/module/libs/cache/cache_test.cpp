/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>

#include "cache/cache.hpp"
#include "endpoint.pb.h"

using namespace iroha::cache;
using namespace iroha::protocol;

const int typicalInsertAmount = 5;

/**
 * @given initialized cache
 * @when insert N ToriiResponse objects into it
 * @then amount of items in cache equals N
 */
TEST(CacheTest, InsertValues) {
  Cache<std::string, ToriiResponse> cache;
  ASSERT_EQ(cache.getCacheItemCount(), 0);
  for (int i = 0; i < typicalInsertAmount; ++i) {
    ToriiResponse response;
    response.set_tx_status(TxStatus::STATELESS_VALIDATION_SUCCESS);
    cache.addItem("abcdefg" + std::to_string(i), response);
  }
  ASSERT_EQ(cache.getCacheItemCount(), typicalInsertAmount);
}

/**
 * @given initialized cache
 * @when insert cache.getIndexSizeHigh() items into it + 1
 * @then after the last insertion amount of items should decrease to
 * cache.getIndexSizeLow()
 */
TEST(CacheTest, InsertMoreThanLimit) {
  Cache<std::string, ToriiResponse> cache;
  for (uint32_t i = 0; i < cache.getIndexSizeHigh(); ++i) {
    ToriiResponse response;
    response.set_tx_status(TxStatus::STATEFUL_VALIDATION_FAILED);
    cache.addItem("abcdefg" + std::to_string(i), response);
  }
  ASSERT_EQ(cache.getCacheItemCount(), cache.getIndexSizeHigh());
  ToriiResponse resp;
  resp.set_tx_status(TxStatus::COMMITTED);
  cache.addItem("1234", resp);
  ASSERT_EQ(cache.getCacheItemCount(), cache.getIndexSizeLow());
}

/**
 * @given initialized cache
 * @when insert N items and then insert 2 with the same hashes
 * @then amount of cache items should not increase after last 2 insertions
 * but their statuses should be updated
 */
TEST(CacheTest, InsertSameHashes) {
  Cache<std::string, ToriiResponse> cache;
  for (int i = 0; i < typicalInsertAmount; ++i) {
    ToriiResponse response;
    response.set_tx_status(TxStatus::NOT_RECEIVED);
    cache.addItem(std::to_string(i), response);
  }
  ToriiResponse resp;
  resp.set_tx_status(TxStatus::COMMITTED);
  cache.addItem("0", resp);
  ASSERT_EQ(cache.getCacheItemCount(), typicalInsertAmount);
  ASSERT_EQ(cache.findItem("0")->tx_status(), TxStatus::COMMITTED);
  cache.addItem("1", resp);
  ASSERT_EQ(cache.getCacheItemCount(), typicalInsertAmount);
  ASSERT_EQ(cache.findItem("1")->tx_status(), TxStatus::COMMITTED);
}

/**
 * @given Initialized cache
 * @when insert N items and find one of them
 * @then item should be found and its status should be the same as before
 * insertion
 */
TEST(CacheTest, FindValues) {
  Cache<std::string, ToriiResponse> cache;
  for (int i = 0; i < typicalInsertAmount; ++i) {
    ToriiResponse response;
    response.set_tx_status(TxStatus::STATEFUL_VALIDATION_SUCCESS);
    cache.addItem(std::to_string(i), response);
  }
  auto item = cache.findItem("2");
  ASSERT_NE(item, boost::none);
  ASSERT_EQ(item->tx_status(), TxStatus::STATEFUL_VALIDATION_SUCCESS);
}

/**
 * @given Initialized cache
 * @when find something in cache
 * @then item should not be found
 */
TEST(CacheTest, FindInEmptyCache) {
  Cache<std::string, ToriiResponse> cache;
  auto item = cache.findItem("0");
  ASSERT_EQ(item, boost::none);
}

/**
 * @given Initialized cache
 * @when insert cache.getIndexSizeHigh() items into it + 1
 * @then the oldest inserted item was in cache initially but not in cache
 * anymore
 */
TEST(CacheTest, FindVeryOldTransaction) {
  Cache<std::string, ToriiResponse> cache;
  ToriiResponse resp;
  resp.set_tx_status(TxStatus::COMMITTED);
  cache.addItem("0", resp);
  ASSERT_EQ(cache.findItem("0")->tx_status(), TxStatus::COMMITTED);
  for (uint32_t i = 0; i < cache.getIndexSizeHigh(); ++i) {
    ToriiResponse response;
    response.set_tx_status(TxStatus::STATEFUL_VALIDATION_FAILED);
    cache.addItem("abcdefg" + std::to_string(i), response);
  }
  ASSERT_EQ(cache.findItem("0"), boost::none);
}

/// Custom key type for the test
struct Key {
  std::string info;

  bool operator==(const Key &a) const {
    return info == a.info;
  }
};

/// Hash strategy for the key type
struct KeyHasher {
  std::size_t operator()(const Key &a) const {
    // dumb hash function
    return a.info.size();
  }
};

/**
 * @given key of custom type with custom hasher
 * @when object with this type is added to cache
 * @then value corresponding to this key is found
 */
TEST(CacheTest, CustomHasher) {
  Cache<Key, std::string, KeyHasher> cache;

  Key key;
  key.info = "key";

  std::string value = "value";

  cache.addItem(key, value);

  auto val = cache.findItem(key);

  ASSERT_TRUE(val);
  ASSERT_EQ(val.value(), value);
}

/**
 * @given initialized cache with given parameters
 * @when insert cache.getIndexSizeHigh() items into it + 1
 * @then after the last insertion amount of items should decrease to
 * cache.getIndexSizeLow()
 */
TEST(CacheTest, InsertCustomSize) {
  Cache<std::string, std::string> cache(1, 1);
  cache.addItem("key", "value");
  ASSERT_EQ(cache.getCacheItemCount(), cache.getIndexSizeHigh());
  auto val = cache.findItem("key");
  ASSERT_TRUE(val);
  ASSERT_EQ(val.value(), "value");
  cache.addItem("key2", "value2");
  ASSERT_EQ(cache.getCacheItemCount(), cache.getIndexSizeLow());
  val = cache.findItem("key");
  ASSERT_FALSE(val);
  ASSERT_TRUE(cache.findItem("key2"));
  ASSERT_EQ(cache.findItem("key2").value(), "value2");
}
