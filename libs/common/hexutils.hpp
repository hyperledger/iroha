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

namespace iroha {

  /**
   * Convert string of raw bytes to printable hex string
   * @param str - raw bytes string to convert
   * @return - converted hex string
   */
  inline std::string bytestringToHexstring(const std::string &str) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (const auto &c : str) {
      ss << std::setw(2) << (static_cast<int>(c) & 0xff);
    }
    return ss.str();
  }

  /**
   * Convert printable hex string to string of raw bytes
   * @param str - hex string to convert
   * @return - raw bytes converted string or boost::noneif provided string
   * was not a correct hex string
   */
  inline iroha::expected::Result<std::string, std::string>
  hexstringToBytestringResult(const std::string &str) {
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
