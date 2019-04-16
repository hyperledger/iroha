/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GENERATOR_HPP
#define IROHA_GENERATOR_HPP

#include <algorithm>

#include "common/blob.hpp"

namespace generator {

  template <size_t size_>
  iroha::blob_t<size_> random_blob(size_t seed) {
    iroha::blob_t<size_> v;
    srand(seed);
    std::generate_n(v.begin(), size_, [] { return rand() % 256; });
    return v;
  }

  /**
   * Generates new random string from lower-case letters
   * @param len - size of string to generate
   * @return generated string
   */
  std::string randomString(size_t len);

}  // namespace generator

#endif  // IROHA_GENERATOR_HPP
