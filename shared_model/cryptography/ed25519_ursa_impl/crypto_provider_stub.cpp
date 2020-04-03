/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"

namespace shared_model {
  namespace crypto {
    Signed CryptoProviderEd25519Ursa::sign(const Blob &blob,
                                           const Keypair &keypair) {
      return Signed{""};
    }

    bool CryptoProviderEd25519Ursa::verify(const Signed &signed_data,
                                           const Blob &orig,
                                           const PublicKey &public_key) {
      return false;
    }

    Keypair CryptoProviderEd25519Ursa::generateKeypair() {
      return Keypair{PublicKey{""}, PrivateKey{""}};
    }

    Keypair CryptoProviderEd25519Ursa::generateKeypair(const Seed &seed) {
      return Keypair{PublicKey{""}, PrivateKey{""}};
    }

    constexpr size_t CryptoProviderEd25519Ursa::kHashLength;
    constexpr size_t CryptoProviderEd25519Ursa::kPublicKeyLength;
    constexpr size_t CryptoProviderEd25519Ursa::kPrivateKeyLength;
    constexpr size_t CryptoProviderEd25519Ursa::kSignatureLength;

  }  // namespace crypto
}  // namespace shared_model
