/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include <tbb/concurrent_queue.h>
#include <iostream>

TEST(TBBTest, ConcurrentQueueUsage) {
  tbb::concurrent_queue<int> queue;
  for (int i = 0; i < 10; ++i) queue.push(i);
  typedef tbb::concurrent_queue<int>::iterator iter;
  for (iter i(queue.unsafe_begin()); i != queue.unsafe_end(); ++i)
    std::cout << *i << " ";
  std::cout << std::endl;
}
