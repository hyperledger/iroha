/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_BLOOM_HPP
#define IROHA_CRYPTO_BLOOM_HPP

#include <string_view>
#include <iostream>
#include <type_traits>

#include "cryptography/hash.hpp"
#include "common/mem_operations.hpp"

namespace shared_model::crypto {

  template <size_t kIndex, size_t kSize>
  class Iroha2BloomHasher64 {
    static_assert(kIndex * sizeof(uint64_t) < kSize, "Unexpected size.");
    static_assert(kSize % sizeof(uint64_t) == 0, "Inconsistent size.");

   public:
    auto operator()(shared_model::crypto::Hash const &hash) const {
      auto const input = *(((uint64_t *)&hash.blob()[0]) + kIndex);
      auto const pack1 = (input >> 32) ^ input;
      auto const pack2 = (pack1 >> 16) ^ pack1;
      return (((pack2 >> 8) ^ pack2) & 0xff);
    }
    void operator()(shared_model::crypto::Hash const &hash,
                    uint8_t (&bloom)[kSize]) const {
      auto const pack3 = (*this)(hash);
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

    template <typename... T>
    struct ArgsListNE {
      static constexpr auto value = sizeof...(T) > 0;
    };

    static constexpr size_t kBytesCount = (kBitsCount >> 3);
    uint8_t filter_[kBytesCount] __attribute__((aligned(16)));

    template <typename Hasher>
    auto checkHash(DataType const &data) const {
      auto const pack = Hasher{}(data);
      auto const byte_position = (pack >> 3);
      auto const bit_position = (pack & 0x7);

      assert(byte_position < kBytesCount);
      auto const &target = *(filter_ + byte_position);
      return ((target & (1 << bit_position)) != 0);
    };

    template <typename Hasher,
              typename... Hashers,
              typename std::enable_if<ArgsListNE<Hashers...>::value,
                                      bool>::type = true>
    auto runHashers(DataType const &data) const {
      return checkHash<Hasher>(data) && runHashers<Hashers...>(data);
    }
    template <typename Hasher>
    auto runHashers(DataType const &data) const {
      return checkHash<Hasher>(data);
    }

   public:
    BloomFilter() {
      clear();
    }

    void set(DataType const &data) {
      ((void)HashFunctions()(data, filter_), ...);
    }

    bool test(DataType const &data) const {
      return runHashers<HashFunctions...>(data);
    }

    void clear() {
      iroha::memzero(filter_);
    }

    void store(std::string_view const &data) {
      if (data.size() == kBytesCount)
        memcpy(filter_, data.data(), kBytesCount);
      else
        throw std::runtime_error("Unexpected Bloom filter size.");
    }

    std::string_view load() {
      return std::string_view(filter_, kBytesCount);
    }
  };

}  // namespace shared_model::crypto

#endif  // IROHA_CRYPTO_BLOOM_HPP
