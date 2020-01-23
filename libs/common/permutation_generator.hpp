/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <random>
#include <vector>

namespace iroha {

  using RandomEngine = std::mt19937_64;

  RandomEngine makeSeededPrng(const char *seed_start, size_t seed_length);

  RandomEngine makeSeededPrng(const unsigned char *seed_start,
                              size_t seed_length);

  /// Helper class to seed a PRNG. For not crypto-related use only.
  class Seeder {
   public:
    using ValueType = RandomEngine::result_type;

    Seeder();

    RandomEngine makePrng() const;

    Seeder &feed(const char *seed_start, size_t seed_length);

    Seeder &feed(ValueType value);

   protected:
    ValueType current_seed_;
  };

  /**
   * Generate permutation of numbers from 0 to @a size - 1.
   * Is guaranteed to generate same permutation on any platform.
   * @param[out] permutation container to store the permutation.
   * @param[in] prng the source of pseudo-random data to generate permutation.
   * @param[in] size the size of permutation to generate.
   */
  void generatePermutation(std::vector<size_t> &permutation,
                           RandomEngine prng,
                           size_t size);
}  // namespace iroha
