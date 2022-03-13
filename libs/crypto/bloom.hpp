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
    static auto pack8(shared_model::crypto::Hash const &hash) {
      auto const input = *(((uint64_t *)&hash.blob()[0]) + kIndex);
      auto const pack1 = (input >> 32) ^ input;
      auto const pack2 = (pack1 >> 16) ^ pack1;
      auto const pack3 = (((pack2 >> 8) ^ pack2) & 0xff);

      assert((pack3 >> 3) < kSize);
      return std::make_pair(pack3 >> 3, pack3 & 0x7);
    }
    static void set(shared_model::crypto::Hash const &hash,
                    uint8_t (&bloom)[kSize]) {
      auto const &[byte_position, bit_position] = pack8(hash);
      auto &target = *(bloom + byte_position);
      target |= (1 << bit_position);
    }
    static bool isSet(shared_model::crypto::Hash const &hash,
               uint8_t const (&bloom)[kSize]) {
      auto const &[byte_position, bit_position] = pack8(hash);
      auto const &target = *(bloom + byte_position);
      return ((target & (1 << bit_position)) != 0);
    }
  };

  template <typename DataType, size_t kBitsCount, typename... HashFunctions>
  class BloomFilter final {
   public:
    static_assert((kBitsCount & 0x7) == 0, "BitsCount must be multiple of 8");
    static_assert(kBitsCount != 0, "BitsCount can not be 0");
    static constexpr size_t kBytesCount = (kBitsCount >> 3);

   private:

    template <typename... T>
    struct ArgsListNE {
      static constexpr auto value = sizeof...(T) > 0;
    };

    uint8_t filter_[kBytesCount] __attribute__((aligned(16)));

    template <typename Hasher>
    auto checkHash(DataType const &data) const {
      return Hasher::isSet(data, filter_);
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
      ((void)HashFunctions::set(data, filter_), ...);
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

    std::string_view load() const {
      return std::string_view((char*)filter_, kBytesCount);
    }
  };

}  // namespace shared_model::crypto

#endif  // IROHA_CRYPTO_BLOOM_HPP
