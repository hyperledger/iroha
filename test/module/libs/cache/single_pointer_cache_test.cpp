/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <thread>

#include <gtest/gtest.h>

#include "cache/single_pointer_cache.hpp"

using namespace iroha::cache;

class SinglePointerCacheTest : public ::testing::Test {
  using SinglePointerIntCache = SinglePointerCache<int>;

 protected:
  void SetUp() override {
    int_cache.release();
  }

  SinglePointerIntCache int_cache;
  const int default_int_value = 5;
  const int run_times{10};
  const std::chrono::milliseconds sleep_interval{100};
};

/**
 * @given empty int cache
 * @when trying to get the value inside
 * @then cache will return nullptr
 */
TEST_F(SinglePointerCacheTest, GetWhenEmpty) {
  ASSERT_FALSE(int_cache.get());
}

/**
 * @given empty int cache
 * @when inserting some value into it @and trying to get it
 * @then cache will return the inserted value
 */
TEST_F(SinglePointerCacheTest, Insert) {
  int_cache.insert(std::make_shared<int>(default_int_value));
  ASSERT_EQ(*int_cache.get(), default_int_value);
}

/**
 * @given empty int cache
 * @when inserting some value into it @and releasing the cache @and trying to
 * get value inside
 * @then cache will return nullptr
 */
TEST_F(SinglePointerCacheTest, Release) {
  int_cache.insert(std::make_shared<int>(default_int_value));
  ASSERT_TRUE(int_cache.get());

  int_cache.release();
  ASSERT_FALSE(int_cache.get());
}

/**
 * @given empty int cache
 * @when first thread inserts value @and another tries to read it @and the first
 * removes it @and second read operation completes
 * @then the system could possibly crash, if it was not thread-safe - it would
 * try to give removed value to the second thread
 */
TEST_F(SinglePointerCacheTest, MultithreadedCache) {
  auto read = [this] {
    // if cache is not empty, read the value; otherwise do nothing
    for (auto i = 0; i < run_times; ++i) {
      auto value_ptr = int_cache.get();
      if (value_ptr) {
        ASSERT_NO_THROW(*value_ptr);
      }
      std::this_thread::sleep_for(sleep_interval);
    }
  };
  auto write_one = [this] {
    // just write to cache
    for (auto i = 0; i < run_times; i++) {
      std::this_thread::sleep_for(sleep_interval);
      int_cache.insert(std::make_shared<int>(i));
    }
  };
  auto write_two = [this] {
    // just write to cache
    for (auto i = run_times; i > 0; --i) {
      std::this_thread::sleep_for(sleep_interval);
      int_cache.insert(std::make_shared<int>(i));
    }
  };
  auto release = [this] {
    // release the cache
    for (auto i = 0; i < run_times; ++i) {
      int_cache.release();
      std::this_thread::sleep_for(sleep_interval);
    }
  };

  std::thread writer_one{write_one}, reader{read}, releaser{release},
      writer_two{write_two};
  writer_one.join();
  reader.join();
  releaser.join();
  writer_two.join();
}
