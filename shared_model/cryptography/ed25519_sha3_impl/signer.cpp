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
    // TODO IR-716 24.04.2020 mboldyrev: make Signer::sign return a Result
    std::string Signer::sign(const Blob &blob, const Keypair &keypair) {
      return iroha::pubkey_t::from_hexstring(keypair.publicKey())
          .match(
              [&](auto &&public_key) {
                return iroha::sign(iroha::sha3_256(crypto::toBinaryString(blob))
                                       .to_string(),
                                   std::move(public_key).value,
                                   iroha::privkey_t::from_raw(
                                       keypair.privateKey().blob().data()))
                    .to_hexstring();
              },
              [](const auto & /* error */) { return std::string{}; });
    }
  }  // namespace crypto
}  // namespace shared_model
