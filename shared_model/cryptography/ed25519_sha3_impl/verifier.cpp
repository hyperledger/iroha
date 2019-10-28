/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/verifier.hpp"

#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace shared_model {
  namespace crypto {
    bool Verifier::verify(const Signed &signedData,
                          const Blob &orig,
                          const PublicKey &publicKey) {
      auto blob_hash = iroha::sha3_256(orig.blob());
      return publicKey.size() == iroha::pubkey_t::size()
          and signedData.size() == iroha::sig_t::size()
          and iroha::verify(blob_hash.data(),
                            blob_hash.size(),
                            iroha::pubkey_t::from_raw(publicKey.blob().data()),
                            iroha::sig_t::from_raw(signedData.blob().data()));
    }
  }  // namespace crypto
}  // namespace shared_model
