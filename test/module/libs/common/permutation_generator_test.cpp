/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common/permutation_generator.hpp"

#include <algorithm>
#include <numeric>
#include <random>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

using namespace iroha;

static const char kSeedString[] = "sector prise on the wheel";

struct TestSeeder : public Seeder {
  ValueType getCurrentSeed() {
    return current_seed_;
  }
};

TEST(PermutationTest, SeederPortable) {
  TestSeeder seeder;
  seeder.feed(kSeedString, sizeof(kSeedString));

  const Seeder::ValueType old_seed = 1836461661050454545ull;
  EXPECT_EQ(seeder.getCurrentSeed(), old_seed);
}

TEST(PermutationTest, PrngPortable) {
  auto prng = makeSeededPrng(kSeedString, sizeof(kSeedString));
  EXPECT_EQ(prng(), 156325153285836724ull);
  EXPECT_EQ(prng(), 13311736527361153936ull);
  EXPECT_EQ(prng(), 18096387757423010509ull);
  EXPECT_EQ(prng(), 7650585443747401588ull);
  EXPECT_EQ(prng(), 11348867370419244846ull);
  EXPECT_EQ(prng(), 2979086026387263581ull);
  EXPECT_EQ(prng(), 14233412580210913118ull);
  EXPECT_EQ(prng(), 8772078191537298753ull);
  EXPECT_EQ(prng(), 17137604657093593059ull);
  EXPECT_EQ(prng(), 12426436247396118143ull);
}

TEST(PermutationTest, PermutationPortable) {
  std::vector<size_t> generated_now;
  generatePermutation(
      generated_now, makeSeededPrng(kSeedString, sizeof(kSeedString)), 10);
  const std::vector<size_t> generated_before{{4, 5, 9, 0, 1, 6, 3, 8, 2, 7}};
  EXPECT_EQ(generated_now, generated_before);
}

using PermutationTestParametricSeed =
    ::testing::TestWithParam<Seeder::ValueType>;

std::vector<Seeder::ValueType> generateRandomNumbers(size_t number) {
  std::vector<Seeder::ValueType> random_numbers;
  random_numbers.reserve(number);

  std::random_device r;
  std::default_random_engine e1(r());

  std::generate_n(
      std::back_inserter(random_numbers), number, [&] { return e1(); });

  return random_numbers;
}

INSTANTIATE_TEST_SUITE_P(Instance,
                         PermutationTestParametricSeed,
                         ::testing::ValuesIn(generateRandomNumbers(100)));

TEST_P(PermutationTestParametricSeed, PermutationValid) {
  static const size_t kSize = 1234;

  std::vector<size_t> permutation;
  generatePermutation(permutation, Seeder{}.feed(GetParam()).makePrng(), kSize);

  EXPECT_EQ(permutation.size(), kSize);

  std::vector<size_t> ascending_ints;
  ascending_ints.resize(kSize);
  std::iota(ascending_ints.begin(), ascending_ints.end(), 0);
  EXPECT_THAT(
      permutation,
      ::testing::WhenSorted(::testing::ElementsAreArray(ascending_ints)));
}
