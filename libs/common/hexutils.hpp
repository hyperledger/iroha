/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_HEXUTILS_HPP
#define IROHA_HEXUTILS_HPP

#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/optional.hpp>
#include "common/result.hpp"
#include "interfaces/common_objects/byte_range.hpp"

namespace iroha {

  /**
   * Convert string of raw bytes to printable hex string
   * @param str - raw bytes string to convert
   * @return - converted hex string
   */
  template <typename OutputContainer>
  inline void bytestringToHexstringAppend(
      const shared_model::interface::types::ByteRange &input,
      OutputContainer &destination) {
    char const *const kDigitsLowerAlpha =
        "000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b1c1d1e1f"
        "202122232425262728292a2b2c2d2e2f"
        "303132333435363738393a3b3c3d3e3f"
        "404142434445464748494a4b4c4d4e4f"
        "505152535455565758595a5b5c5d5e5f"
        "606162636465666768696a6b6c6d6e6f"
        "707172737475767778797a7b7c7d7e7f"
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f"
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
        "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf"
        "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf"
        "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
        "e0e1e2e3e4e5e6e7e8e9eaebecedeeef"
        "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";

    const auto output_offset = destination.size();
    destination.resize(destination.size() + input.size() * 2);
    auto *output_it = destination.data() + output_offset;
    for (const auto &c : input) {
      const char *hex_pos = &kDigitsLowerAlpha[static_cast<int>(c) * 2];
      *output_it++ = *hex_pos++;
      *output_it++ = *hex_pos;
    }
  }

  /**
   * Convert string of raw bytes to printable hex string
   * @param str - raw bytes string to convert
   * @return - converted hex string
   */
  inline std::string bytestringToHexstring(const std::string_view &str) {
    std::string result;
    bytestringToHexstringAppend(
        shared_model::interface::types::ByteRange{
            reinterpret_cast<const std::byte *>(str.data()), str.size()},
        result);
    return result;
  }

  /**
   * Convert printable hex string to string of raw bytes
   * @param str - hex string to convert
   * @return - raw bytes converted string or boost::noneif provided string
   * was not a correct hex string
   */
  inline iroha::expected::Result<std::string, const char *>
  hexstringToBytestringResult(const std::string_view &str) {
    using namespace iroha::expected;
    if (str.empty()) {
      return makeError("Empty hex string.");
    }
    if (str.size() % 2 != 0) {
      return makeError("Hex string contains uneven number of characters.");
    }
    std::string result;
    result.reserve(str.size() / 2);
    try {
      boost::algorithm::unhex(
          str.begin(), str.end(), std::back_inserter(result));
    } catch (const boost::algorithm::hex_decode_error &e) {
      return makeError(e.what());
    }
    return iroha::expected::makeValue(std::move(result));
  }

  [[deprecated]] inline boost::optional<std::string> hexstringToBytestring(
      const std::string &str) {
    return iroha::expected::resultToOptionalValue(
        hexstringToBytestringResult(str));
  }

}  // namespace iroha

#endif  // IROHA_HEXUTILS_HPP
