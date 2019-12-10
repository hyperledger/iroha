/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_SHA3_512_HPP
#define IROHA_SHARED_MODEL_SHA3_512_HPP

#include "common/types.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace shared_model {
  namespace crypto {
    class Sha3_512 {
     public:
      static Hash makeHash(const Blob &blob) {
        Blob::Bytes bytes;
        bytes.resize(hash512_t::size());
        iroha::sha3_512(bytes.data(), blob.data(), blob.size());
        return Hash(std::make_unique<Blob>(std::move(bytes));
      }
    };
  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_SHA3_512_HPP
