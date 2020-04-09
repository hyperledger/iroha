/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/verifier.hpp"

#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/internal/sha3_hash.hpp"

using shared_model::interface::types::PublicKeyByteRangeView;
using shared_model::interface::types::SignatureByteRangeView;

namespace shared_model {
  namespace crypto {
    bool Verifier::verify(SignatureByteRangeView signature,
                          const Blob &orig,
                          PublicKeyByteRangeView public_key) {
      auto blob_hash = iroha::sha3_256(orig.blob());
      return iroha::verify(
          blob_hash.data(), blob_hash.size(), public_key, signature);
    }
  }  // namespace crypto
}  // namespace shared_model
