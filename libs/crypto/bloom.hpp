/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_BLOOM_HPP
#define IROHA_CRYPTO_BLOOM_HPP

#include <string_view>

#include "cryptography/hash.hpp"
#include "common/mem_operations.hpp"

namespace shared_model::crypto {

  template <size_t kIndex, size_t kSize>
  class Iroha2BloomHasher64 {
    static_assert(kIndex * sizeof(uint64_t) < kSize, "Unexpected size.");
    static_assert(kSize % sizeof(uint64_t) == 0, "Inconsistent size.");

   public:
    void operator()(shared_model::crypto::Hash const &hash,
                    uint8_t (&bloom)[kSize]) const {
      auto const input = *(((uint64_t *)&hash.blob()[0]) + kIndex);
      auto const pack1 = (input >> 32) ^ input;
      auto const pack2 = (pack1 >> 16) ^ pack1;
      auto const pack3 = ((pack2 >> 8) ^ pack2) & 0xff;

      auto const byte_position = (pack3 >> 3);
      auto const bit_position = (pack3 & 0x7);

      assert(byte_position < kSize);
      auto &target = *(bloom + byte_position);

      target |= (1 << bit_position);
    }
  };

  template <typename DataType, size_t kBitsCount, typename... HashFunctions>
  class BloomFilter final {
    static_assert((kBitsCount & 0x7) == 0, "BitsCount must be multiple of 8");
    static_assert(kBitsCount != 0, "BitsCount can not be 0");

    static constexpr size_t kBytesCount = (kBitsCount >> 3);
    uint8_t filter_[kBytesCount] __attribute__((aligned(16)));

   public:
    BloomFilter() {
      clear();
    }

    void set(DataType const &data) {
      ((void)HashFunctions()(data, filter_), ...);
    }

    bool test(DataType const &data) const {
      uint8_t filter[kBytesCount] __attribute__((aligned(16)));
      memzero(filter);
      ((void)HashFunctions()(data, filter), ...);

      for (size_t ix = 0; ix < kBytesCount / sizeof(uint64_t); ++ix) {
        auto const value1 = ((uint64_t *)filter_)[ix];
        auto const value2 = ((uint64_t *)filter)[ix];
        if ((value1 & value2) != value2)
          return false;
      }

      return true;
    }

    void clear() {
      iroha::memzero(filter_);
    }

    std::basic_string_view<uint64_t> get() {
      return std::basic_string_view<uint64_t>(filter_, kBytesCount);
    }
  };

}  // namespace shared_model::crypto

#endif  // IROHA_CRYPTO_BLOOM_HPP
