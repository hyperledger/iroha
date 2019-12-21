/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "generator/generator.hpp"

#include <algorithm>
#include <cstdlib>

namespace generator {

  std::string randomString(size_t len) {
    std::string str(len, 0);
    std::generate_n(
        str.begin(), len, []() { return 'a' + std::rand() % ('z' - 'a' + 1); });
    return str;
  }

}  // namespace generator
