/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_HEXUTILS_HPP
#define IROHA_HEXUTILS_HPP

#include <ciso646>
#include <iomanip>
#include <sstream>
#include <string>

#include <boost/optional.hpp>

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
  inline boost::optional<std::string> hexstringToBytestring(
      const std::string &str) {
    if (str.empty() or str.size() % 2 != 0) {
      return boost::none;
    }
    std::string result(str.size() / 2, 0);
    for (size_t i = 0; i < result.length(); ++i) {
      std::string byte = str.substr(i * 2, 2);
      size_t pos = 0;  // processed characters count
      try {
        result.at(i) =
            static_cast<std::string::value_type>(std::stoul(byte, &pos, 16));
      } catch (const std::invalid_argument &) {
        return boost::none;
      } catch (const std::out_of_range &) {
        return boost::none;
      }
      if (pos != byte.size()) {
        return boost::none;
      }
    }
    return result;
  }

}  // namespace iroha

#endif  // IROHA_HEXUTILS_HPP
