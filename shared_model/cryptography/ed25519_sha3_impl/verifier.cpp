/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "verifier.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace shared_model {
  namespace crypto {
    bool Verifier::verify(const Signed &signedData,
                          const Blob &orig,
                          const PublicKey &publicKey) {
      return iroha::verify(
          iroha::sha3_256(crypto::toBinaryString(orig)).to_string(),
          iroha::pubkey_t::from_string(toBinaryString(publicKey)),
          iroha::sig_t::from_string(toBinaryString(signedData)));
    }
  }  // namespace crypto
}  // namespace shared_model
