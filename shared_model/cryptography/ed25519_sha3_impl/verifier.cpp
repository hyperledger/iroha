/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/verifier.hpp"

#include "cryptography/bytes_view.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

namespace shared_model {
  namespace crypto {
    bool Verifier::verify(const Signed &signed_data,
                          const BytesView &orig,
                          const PublicKey &pubkey) {
      auto blob_hash = iroha::sha3_256(orig.byteRange());
      return pubkey.blob().size() == iroha::PubkeyView::size()
          and signed_data.blob().size() == iroha::SigView::size()
          and iroha::verify(blob_hash.data(),
                            blob_hash.size(),
                            iroha::PubkeyView(pubkey.blob().data()),
                            iroha::SigView(signed_data.blob().data()));
    }
  }  // namespace crypto
}  // namespace shared_model
