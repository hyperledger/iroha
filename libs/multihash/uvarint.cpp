/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "uvarint.hpp"

#include "hexutil.hpp"

using kagome::common::hex_upper;

namespace libp2p {
  namespace multi {

    UVarint::UVarint(uint64_t number) {
      bytes_.resize(8);
      size_t i = 0;
      size_t size = 0;
      for (; i < 8; i++) {
        bytes_[i] = static_cast<uint8_t>((number & 0xFFul) | 0x80ul);
        number >>= 7ul;
        if (number == 0) {
          bytes_[i] &= 0x7Ful;
          size = i + 1;
          break;
        }
      }
      bytes_.resize(size);
    }

    UVarint::UVarint(const std::vector<uint8_t> &varint_bytes)
        : bytes_(varint_bytes.begin(),
                 varint_bytes.begin() + calculateSize(varint_bytes)) {}

    UVarint::UVarint(const std::vector<uint8_t> &varint_bytes,
                     int64_t varint_size)
        : bytes_(varint_bytes.begin(), varint_bytes.begin() + varint_size) {}

    boost::optional<UVarint> UVarint::create(
        const std::vector<uint8_t> &varint_bytes) {
      if (varint_bytes.empty()) {
        return {};
      }
      // no use of calculateSize(..), as it is unsafe in this case
      int64_t s = 0;
      while ((varint_bytes[s] & 0x80u) != 0) {
        ++s;
        if (s >= varint_bytes.size()) {
          return {};
        }
      }
      return UVarint{varint_bytes, s + 1};
    }

    uint64_t UVarint::toUInt64() const {
      uint64_t res = 0;
      for (size_t i = 0; i < 8 && i < bytes_.size(); i++) {
        res |= ((bytes_[i] & 0x7ful) << (7 * i));
        if ((bytes_[i] & 0x80ul) == 0) {
          return res;
        }
      }
      return -1;
    }

    const std::vector<uint8_t> &UVarint::toBytes() const {
      return bytes_;
    }

    std::string UVarint::toHex() const {
      return hex_upper(bytes_);
    }

    size_t UVarint::size() const {
      return bytes_.size();
    }

    UVarint &UVarint::operator=(uint64_t n) {
      *this = UVarint(n);
      return *this;
    }

    size_t UVarint::calculateSize(const std::vector<uint8_t> &varint_bytes) {
      size_t s = 0;

      while ((varint_bytes[s] & 0x80u) != 0) {
        s++;
      }
      return s + 1;
    }

  }  // namespace multi
}  // namespace libp2p
