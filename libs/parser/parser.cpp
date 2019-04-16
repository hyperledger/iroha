/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "parser/parser.hpp"

#include <cctype>
#include <ciso646>

namespace parser {

  bool isIntNumber(const std::string &s) {
    return !s.empty()
        && std::find_if(
               s.begin(), s.end(), [](char c) { return not std::isdigit(c); })
        == s.end();
  }

  boost::optional<std::string> parseFirstCommand(std::string line) {
    auto vec = split(line);
    if (vec.size() == 0) {
      return boost::none;
    }
    return vec[0];
  }

  std::vector<std::string> split(std::string line) {
    std::transform(line.begin(), line.end(), line.begin(), ::tolower);
    std::istringstream iss(line);
    return {std::istream_iterator<std::string>{iss},
            std::istream_iterator<std::string>{}};
  }
}  // namespace parser
