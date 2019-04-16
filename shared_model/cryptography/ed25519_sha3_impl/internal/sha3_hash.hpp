/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_HASH_H
#define IROHA_HASH_H

#include <string>
#include <vector>

#include "crypto/hash_types.hpp"

namespace iroha {

  void sha3_256(uint8_t *output, const uint8_t *input, size_t in_size);
  void sha3_512(uint8_t *output, const uint8_t *input, size_t in_size);

  hash256_t sha3_256(const uint8_t *input, size_t in_size);
  hash256_t sha3_256(const std::string &msg);
  hash256_t sha3_256(const std::vector<uint8_t> &msg);
  hash512_t sha3_512(const uint8_t *input, size_t in_size);
  hash512_t sha3_512(const std::string &msg);
  hash512_t sha3_512(const std::vector<uint8_t> &msg);
}  // namespace iroha

#endif  // IROHA_HASH_H
