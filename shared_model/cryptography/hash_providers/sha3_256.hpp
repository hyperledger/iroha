/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SHA3_256_HPP
#define IROHA_SHARED_MODEL_SHA3_256_HPP

#include "crypto/hash_types.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace crypto {
    class Sha3_256 {
     public:
      static Hash makeHash(const BytesView &blob) {
        Blob::Bytes bytes;
        bytes.resize(hash256_t::size());
        iroha::sha3_256(bytes.data(), blob.data(), blob.size());
        return Hash(std::make_unique<Blob>(std::move(bytes));
      }
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_SHA3_256_HPP
