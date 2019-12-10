/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"

#include <ed25519/ed25519.h>

#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace iroha {

  /**
   * Sign the message
   */
  sig_t sign(shared_model::interface::types::ConstByteRange msg,
             const PubkeyView &pub,
             const PrivkeyView &priv) {
    sig_t sig;
    ed25519_sign(reinterpret_cast<signature_t *>(sig.data()),
                 msg.begin(),
                 boost::size(msg),
                 reinterpret_cast<const public_key_t *>(pub.data()),
                 reinterpret_cast<const private_key_t *>(priv.data()));
    return sig;
  }

  /**
   * Verify signature
   */
  bool verify(shared_model::interface::types::ConstByteRange msg,
              const PubkeyView &pub,
              const SigView &sig) {
    return 1
        == ed25519_verify(reinterpret_cast<const signature_t *>(sig.data()),
                          msg.begin(),
                          msg.end() - msg.begin(),
                          reinterpret_cast<const public_key_t *>(pub.data()));
  }

  /**
   * Generate seed
   */
  blob_t<32> create_seed() {
    blob_t<32> seed;
    randombytes(seed.data(), seed.size());
    return seed;
  }

  /**
   * Create keypair
   */
  keypair_t create_keypair(blob_t<32> seed) {
    keypair_t kp;
    kp.privkey = seed;

    ed25519_derive_public_key(
        reinterpret_cast<const private_key_t *>(kp.privkey.data()),
        reinterpret_cast<public_key_t *>(kp.pubkey.data()));

    return kp;
  }

  keypair_t create_keypair() {
    return create_keypair(create_seed());
  }
}  // namespace iroha
