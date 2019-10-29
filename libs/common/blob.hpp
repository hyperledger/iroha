/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_BLOB_HPP
#define IROHA_COMMON_BLOB_HPP

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>

#include "common/hexutils.hpp"
#include "common/result.hpp"

namespace iroha {
  using BadFormatException = std::invalid_argument;
  using byte_t = uint8_t;

  namespace {
    static const std::string code = {'0',
                                     '1',
                                     '2',
                                     '3',
                                     '4',
                                     '5',
                                     '6',
                                     '7',
                                     '8',
                                     '9',
                                     'a',
                                     'b',
                                     'c',
                                     'd',
                                     'e',
                                     'f'};
  }

  /**
   * Base type which represents blob of fixed size.
   *
   * std::string is convenient to use but it is not safe.
   * We can not specify the fixed length for string.
   *
   * For std::array it is possible, so we prefer it over std::string.
   */
  template <size_t size_>
  class blob_t : public std::array<byte_t, size_> {
   public:
    /**
     * Initialize blob value
     */
    blob_t() {
      this->fill(0);
    }

    /**
     * In compile-time returns size of current blob.
     */
    constexpr static size_t size() {
      return size_;
    }

    /**
     * Converts current blob to std::string
     */
    std::string to_string() const noexcept {
      return std::string{this->begin(), this->end()};
    }

    /**
     * Converts current blob to hex string.
     */
    std::string to_hexstring() const noexcept {
      std::string res(size_ * 2, 0);
      auto ptr = this->data();
      for (uint32_t i = 0, k = 0; i < size_; i++) {
        const auto front = (uint8_t)(ptr[i] & 0xF0) >> 4;
        const auto back = (uint8_t)(ptr[i] & 0xF);
        res[k++] = code[front];
        res[k++] = code[back];
      }
      return res;
    }

    static blob_t<size_> from_raw(const byte_t data[size_]) {
      blob_t<size_> b;
      std::copy(data, data + size_, b.begin());
      return b;
    }

    static expected::Result<blob_t<size_>, std::string> from_string(
        const std::string &data) {
      if (data.size() != size_) {
        return expected::makeError(
            std::string{"blob_t: input string has incorrect length. Found: "}
            + std::to_string(data.size())
            + +", required: " + std::to_string(size_));
      }
      return from_raw(reinterpret_cast<const byte_t *>(data.data()));
    }

    static expected::Result<blob_t<size_>, std::string> from_hexstring(
        const std::string &hex) {
      auto bytes = iroha::hexstringToBytestring(hex);
      if (not bytes) {
        return expected::makeError(
            std::string{"Provided data ("} + hex
            + ") is not a valid hex value for blob of size ("
            + std::to_string(size_) + ").");
      }
      return from_string(*bytes);
    }
  };
}  // namespace iroha

#endif  // IROHA_COMMON_BLOB_HPP
