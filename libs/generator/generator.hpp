/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GENERATOR_HPP
#define IROHA_GENERATOR_HPP

#include <string>

namespace generator {

  /**
   * Generates new random string from lower-case letters
   * @param len - size of string to generate
   * @return generated string
   */
  std::string randomString(size_t len);

}  // namespace generator

#endif  // IROHA_GENERATOR_HPP
