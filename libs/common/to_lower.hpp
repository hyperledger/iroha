/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TO_LOWER_HPP
#define IROHA_TO_LOWER_HPP

#include <string>

namespace iroha {

  inline std::string &toLowerAppend(std::string_view src, std::string &dst) {
    dst.reserve(dst.size() + src.size());
    for (auto const c : src) dst += std::tolower(c);
    return dst;
  }

}  // namespace iroha
#endif  // IROHA_TO_LOWER_HPP
