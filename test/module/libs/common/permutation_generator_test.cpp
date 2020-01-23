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

TEST(ShufflerTest, StdSeedSeqPortable) {
  std::vector<size_t> generated_now(10, 0);
  std::seed_seq(kSeedString, kSeedString + sizeof(kSeedString))
      .generate(generated_now.begin(), generated_now.end());

  std::vector<size_t> generated_before{{3500580016,
                                        2487152681,
                                        890682050,
                                        2703780814,
                                        180547361,
                                        4244110869,
                                        995692298,
                                        2794135049,
                                        28909055,
                                        3881973278}};
  EXPECT_EQ(generated_now, generated_before);
}

TEST(PermutationTest, SeederPortable) {
  TestSeeder seeder;
  seeder.feed(kSeedString, sizeof(kSeedString));

  const Seeder::ValueType old_seed = 18321097469817268575ull;
  EXPECT_EQ(seeder.getCurrentSeed(), old_seed);
}

TEST(PermutationTest, PrngPortable) {
  auto prng = makeSeededPrng(kSeedString, sizeof(kSeedString));
  EXPECT_EQ(prng(), 18411566977080829358ull);
  EXPECT_EQ(prng(), 1542867733836066154ull);
  EXPECT_EQ(prng(), 14957448015533108087ull);
  EXPECT_EQ(prng(), 9726285800433590021ull);
  EXPECT_EQ(prng(), 7000960477383894054ull);
  EXPECT_EQ(prng(), 13774377099739194617ull);
  EXPECT_EQ(prng(), 9855892305214809794ull);
  EXPECT_EQ(prng(), 4375420897913288132ull);
  EXPECT_EQ(prng(), 3961499137579268468ull);
  EXPECT_EQ(prng(), 563129626573376221ull);
}

TEST(PermutationTest, StdShufflePortable) {
  std::vector<size_t> generated_now(10, 0);
  std::iota(generated_now.begin(), generated_now.end(), 0);

  auto prng = makeSeededPrng(kSeedString, sizeof(kSeedString));
  std::shuffle(generated_now.begin(), generated_now.end(), prng);

  const std::vector<size_t> generated_before{{5, 3, 0, 8, 9, 7, 1, 2, 6, 4}};
  EXPECT_EQ(generated_now, generated_before);
}

TEST(PermutationTest, PermutationPortable) {
  std::vector<size_t> generated_now;
  generatePermutation(
      generated_now, makeSeededPrng(kSeedString, sizeof(kSeedString)), 10);
  const std::vector<size_t> generated_before{{8, 9, 5, 4, 6, 2, 1, 7, 0, 3}};
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
