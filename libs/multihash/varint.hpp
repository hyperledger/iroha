/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MULTIHASH_VARINT_HPP
#define IROHA_MULTIHASH_VARINT_HPP

#include "interfaces/common_objects/byte_range.hpp"

namespace iroha {
  namespace multihash {

    /**
     * Try to read single varint int from buffer.
     * https://github.com/multiformats/unsigned-varint#format
     * @tparam NumberType some integer type
     * @param[in|out] buffer which contains the varint int in the beginning. the
     * variable will be overwritten with the rest of the data after the number
     * just read.
     * @param[out] number the read number on success.
     * @return true if successfully read the number, false otherwise
     */
    template <typename NumberType>
    inline bool readVarInt(shared_model::interface::types::ByteRange &buffer,
                           NumberType &number) {
      if (buffer.empty()) {
        return false;
      }
      number = 0;
      constexpr NumberType kSignificantBitsMask{0x7F};
      constexpr std::byte kContinuationBitMask{0x80};
      constexpr size_t kMaxVarIntLength = 8;
      for (size_t i = 0; i < kMaxVarIntLength && i < buffer.size(); i++) {
        if (i >= buffer.size()) {
          return false;
        }
        number |= ((static_cast<NumberType>(buffer[i]) & kSignificantBitsMask)
                   << (7 * i));
        if ((buffer[i] & kContinuationBitMask) == std::byte{0}) {
          const size_t read_bytes = i + 1;
          buffer = shared_model::interface::types::ByteRange{
              buffer.data() + read_bytes, buffer.size() - read_bytes};
          return true;
        }
      }
      return false;
    }

    template <typename NumberType, typename Container>
    inline void encodeVarInt(NumberType number, Container &buffer) {
      constexpr NumberType kSignificantBitsMask{0x7F};
      constexpr NumberType kContinuationBitMask{0x80};

      do {
        NumberType next = number >> 7;
        number &= kSignificantBitsMask;
        if (next != 0) {
          number |= kContinuationBitMask;
        }
        buffer.push_back(static_cast<std::byte>(number));
        number = next;
      } while (number != 0);
    }

  }  // namespace multihash
}  // namespace iroha

#endif
