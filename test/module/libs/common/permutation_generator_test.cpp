/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <random>
#include <vector>

#include <gtest/gtest.h>

namespace {
  std::vector<size_t> generate_permutation(const std::string &hash_seed,
                                           size_t size) {
    std::vector<size_t> permutation;
    permutation.resize(size);
    std::iota(permutation.begin(), permutation.end(), 0);

    std::seed_seq seed(hash_seed.begin(), hash_seed.end());
    std::default_random_engine gen(seed);

    std::shuffle(permutation.begin(), permutation.end(), gen);
    return permutation;
  }
}  // namespace

TEST(ShufflerTest, Portable) {
  auto generated_now = generate_permutation("sector prise on the wheel", 10);
  std::vector<size_t> generated_before{{2, 6, 1, 7, 3, 8, 9, 0, 5, 4}};
  EXPECT_EQ(generated_now, generated_before);
}
