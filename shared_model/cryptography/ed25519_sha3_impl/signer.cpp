/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/signer.hpp"

#include "crypto/hash_types.hpp"
#include "cryptography/bytes_view.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace shared_model {
  namespace crypto {
    Signed Signer::sign(const BytesView &blob, const Keypair &keypair) {
      assert(keypair.publicKey().blob().size() == iroha::pubkey_t::size());
      assert(keypair.privateKey().blob().size() == iroha::privkey_t::size());
      return Signed{std::make_shared<shared_model::crypto::Blob>(
          iroha::sign(
              iroha::sha3_256(blob.byteRange()).getView().byteRange(),
              iroha::PubkeyView(keypair.publicKey().blob().byteRange()),
              iroha::PrivkeyView(keypair.privateKey().blob().byteRange()))
              .getView()
              .byteRange())};
    }
  }  // namespace crypto
}  // namespace shared_model
