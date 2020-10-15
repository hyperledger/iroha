/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MULTIHASH_VARINT_HPP
#define IROHA_MULTIHASH_VARINT_HPP

#include <cassert>
#include <cstddef>
#include "interfaces/common_objects/byte_range.hpp"

namespace iroha {
  namespace multihash {

    /**
     * Try to read single varint int from buffer.
     * https://github.com/multiformats/unsigned-varint#format
     * @tparam NumberType some unsigned integer type
     * @param[in|out] buffer which contains the varint int in the beginning. the
     * variable will be overwritten with the rest of the data after the number
     * just read.
     * @param[out] number the read number on success, undefined on error.
     * @return true if successfully read the number, false otherwise
     */
    template <typename NumberType>
    inline bool readVarInt(shared_model::interface::types::ByteRange &buffer,
                           NumberType &number) {
      static_assert(not std::is_signed<NumberType>::value,
                    "VarInt must be unsigned.");

      if (buffer.empty()) {
        return false;
      }
      number = 0;
      constexpr std::byte kSignificantBitsMask{0x7F};
      constexpr std::byte kContinuationBitMask{0x80};
      constexpr size_t kMaxVarIntLength = 8;

      /// How many varint bytes can a number of NumberType occupy.
      /// This is basically ceil(sizeof(number) * 8 / 7).
      constexpr size_t kTargetCapacityVarIntChunks =
          ((sizeof(number) << size_t(3)) + size_t(6)) / size_t(7);
      /// How much bytes are we going to read at most.
      const size_t kMaxPayloadSize =
          std::min(kTargetCapacityVarIntChunks,
                   std::min(kMaxVarIntLength, buffer.size()));
      auto const *const beg = buffer.data();
      auto const *const end = beg + kMaxPayloadSize;
      auto const *ptr = beg;
      bool is_last_block_read = false;
      size_t bytes_read = 0;

      do {
        number |= (static_cast<NumberType>(*ptr & kSignificantBitsMask)
                   << (size_t(7) * bytes_read++));
        is_last_block_read = std::byte(0) == (*ptr++ & kContinuationBitMask);
      } while (not is_last_block_read && ptr != end);

      if (is_last_block_read) {
        assert(bytes_read == static_cast<size_t>(ptr - beg));
        buffer = shared_model::interface::types::ByteRange{
            beg + bytes_read, buffer.size() - bytes_read};
      }
      return is_last_block_read;
    }

    /**
     * Append a single varint int to a buffer.
     * https://github.com/multiformats/unsigned-varint#format
     * @tparam NumberType some unsigned integer type
     * @tparam Container destination byte string container type
     * @param[in] number to encode
     * @param[out] buffer to write to
     */
    template <typename NumberType, typename Container>
    inline void encodeVarInt(NumberType number, Container &buffer) {
      static_assert(not std::is_signed<NumberType>::value,
                    "VarInt must be unsigned.");

      constexpr NumberType kSignificantBitsMask{0x7F};
      constexpr NumberType kContinuationBitMask{0x80};

      do {
        NumberType next = number >> 7;
        number &= kSignificantBitsMask;
        number |= kContinuationBitMask;
        buffer.push_back(static_cast<std::byte>(number));
        number = next;
      } while (number != 0);
      *std::prev(buffer.end()) &= static_cast<std::byte>(~kContinuationBitMask);
    }

  }  // namespace multihash
}  // namespace iroha

#endif
