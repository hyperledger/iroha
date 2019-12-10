/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ed25519/ed25519/sha256.h>
#include <ed25519/ed25519/sha512.h>

#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace iroha {

  void sha3_256(uint8_t *output,
                shared_model::interface::types::ConstByteRange input) {
    sha256(output, input.begin(), boost::size(input));
  }

  void sha3_512(uint8_t *output,
                shared_model::interface::types::ConstByteRange input) {
    sha512(output, input.begin(), boost::size(input));
  }

  hash256_t sha3_256(shared_model::interface::types::ConstByteRange input) {
    hash256_t h;
    sha3_256(h.data(), input);
    return h;
  }

  hash512_t sha3_512(shared_model::interface::types::ConstByteRange input) {
    hash512_t h;
    sha3_512(h.data(), input);
    return h;
  }

}  // namespace iroha
