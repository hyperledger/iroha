/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <algorithm>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

#include <boost/optional.hpp>

#ifndef IROHA_PARSER_HPP
#define IROHA_PARSER_HPP

namespace parser {

  /**
   * Check if string is actually the integer number
   * @param s
   * @return
   */
  bool isIntNumber(const std::string &s);

  /**
   * Parse the first command in the line
   * @param line string to parse
   * @return nullopt if no command found, string otherwise
   */
  boost::optional<std::string> parseFirstCommand(std::string line);

  /**
   * Split line into words
   * @param line
   * @return vector with words
   */
  std::vector<std::string> split(std::string line);

  template <typename T>
  boost::optional<T> parseValue(std::string word) {
    std::stringstream ss(word);
    if (not isIntNumber(word)) {
      return boost::none;
    }
    T val;
    if (ss >> val) {
      return val;
    } else {
      return boost::none;
    }
  }

}  // namespace parser

#endif  // IROHA_PARSER_HPP
