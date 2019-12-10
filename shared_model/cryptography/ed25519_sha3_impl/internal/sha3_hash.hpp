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

  void sha3_256(uint8_t *output,
                shared_model::interface::types::ConstByteRange input);
  void sha3_512(uint8_t *output,
                shared_model::interface::types::ConstByteRange input);

  hash256_t sha3_256(shared_model::interface::types::ConstByteRange input);
  hash512_t sha3_512(shared_model::interface::types::ConstByteRange input);
}  // namespace iroha

#endif  // IROHA_HASH_H
