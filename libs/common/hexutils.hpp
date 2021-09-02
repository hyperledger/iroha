/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_HEXUTILS_HPP
#define IROHA_HEXUTILS_HPP

#include <iterator>
#include <string>

#include <boost/algorithm/hex.hpp>
#include <boost/optional.hpp>
#include "common/result.hpp"
#include "interfaces/common_objects/byte_range.hpp"

namespace iroha {

  template <typename Container>
  inline auto hexstringToBytestringSize(Container const &c)
      -> decltype(c.size()) {
    return (c.size() + 1) / 2;
  }

  template <typename Container>
  inline auto bytestringToHexstringSize(Container const &c)
      -> decltype(c.size()) {
    return c.size() * 2;
  }

  /**
   * Convert string of raw bytes to printable hex string
   * @param str - raw bytes string to convert
   * @return - converted hex string
   */
  template <typename OutputContainer>
  inline void bytestringToHexstringAppend(
      shared_model::interface::types::ByteRange input,
      OutputContainer &destination) {
    static_assert(sizeof(*input.data()) == sizeof(uint8_t), "type mismatch");
    const auto beg = reinterpret_cast<const uint8_t *>(input.data());
    const auto end = beg + input.size();
    destination.reserve(destination.size() + bytestringToHexstringSize(input));
    boost::algorithm::hex_lower(beg, end, std::back_inserter(destination));
  }

  /**
   * Convert string of raw bytes to printable hex string
   * @param str - raw bytes string to convert
   * @return - converted hex string
   */
  inline std::string bytestringToHexstring(std::string_view str) {
    std::string result;
    bytestringToHexstringAppend(
        shared_model::interface::types::makeByteRange(str), result);
    return result;
  }

  /**
   * Convert printable hex string to string of raw bytes
   * @param str - hex string to convert
   * @return - raw bytes converted string or boost::noneif provided string
   * was not a correct hex string
   */
  inline iroha::expected::Result<std::string, const char *>
  hexstringToBytestringResult(std::string_view str) {
    using namespace iroha::expected;
    if (str.empty()) {
      return makeError("Empty hex string.");
    }
    if (str.size() % 2 != 0) {
      return makeError("Hex string contains uneven number of characters.");
    }
    std::string result;
    result.reserve(hexstringToBytestringSize(str));
    try {
      boost::algorithm::unhex(
          str.begin(), str.end(), std::back_inserter(result));
    } catch (const boost::algorithm::hex_decode_error &e) {
      return makeError(e.what());
    }
    return iroha::expected::makeValue(std::move(result));
  }

  /*[[deprecated]]*/ inline boost::optional<std::string> hexstringToBytestring(
      std::string_view str) {
    return iroha::expected::resultToOptionalValue(
        hexstringToBytestringResult(str));
  }

  /**
   * Convert a number to a printable hex string
   * @param val - numeric type value
   * @return - converted hex string
   */
  template <typename T,
            typename = std::enable_if_t<std::is_arithmetic<T>::value>>
  inline std::string numToHexstring(const T val) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(sizeof(T) * 2) << val;
    return ss.str();
  }

}  // namespace iroha

#endif  // IROHA_HEXUTILS_HPP
