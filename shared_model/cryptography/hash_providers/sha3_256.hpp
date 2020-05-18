/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SHA3_256_HPP
#define IROHA_SHARED_MODEL_SHA3_256_HPP

#include "crypto/hash_types.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace crypto {
    class Sha3_256 {
     public:
      enum { kHashLength = 32 };
      static Hash makeHash(const Blob &blob) {
        return Hash(iroha::sha3_256(blob.blob()).to_string());
      }
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SHA3_256_HPP
