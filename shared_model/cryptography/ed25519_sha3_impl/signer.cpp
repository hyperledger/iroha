/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/signer.hpp"
#include "crypto/hash_types.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace shared_model {
  namespace crypto {
    Signed Signer::sign(const Blob &blob, const Keypair &keypair) {
      return Signed(
          iroha::sign(
              iroha::sha3_256(crypto::toBinaryString(blob)).to_string(),
              iroha::pubkey_t::from_string(toBinaryString(keypair.publicKey())),
              iroha::privkey_t::from_string(
                  toBinaryString(keypair.privateKey())))
              .to_string());
    }
  }  // namespace crypto
}  // namespace shared_model
