/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TO_LOWER_HPP
#define IROHA_TO_LOWER_HPP

#include <cassert>
#include <string>

namespace iroha {

  inline std::string &toLowerAppend(std::string_view src, std::string &dst) {
    dst.reserve(dst.size() + src.size());
    for (auto const c : src) dst += std::tolower(c);
    return dst;
  }

  template <size_t N>
  inline std::string_view toLower(std::string_view src, char (&dst)[N]) {
    assert(N >= src.size());

    char const *from = src.data();
    char const *const end = src.data() + src.size();
    char *ptr = dst;

    while (from != end) *ptr++ = std::tolower(*from++);

    return std::string_view(dst, src.size());
  }

}  // namespace iroha
#endif  // IROHA_TO_LOWER_HPP
