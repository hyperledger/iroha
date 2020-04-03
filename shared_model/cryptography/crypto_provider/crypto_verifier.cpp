/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/crypto_provider/crypto_verifier.hpp"

#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"
#include "multihash/multihash.hpp"

using namespace shared_model::crypto;

bool CryptoVerifier::verify(const Signed &signedData,
                            const Blob &source,
                            const PublicKey &pubKey) {
  if (pubKey.blob().size()
      == shared_model::crypto::CryptoProviderEd25519Sha3::kPublicKeyLength) {
    return CryptoProviderEd25519Sha3::verify(signedData, source, pubKey);
  } else if (auto opt_multihash = iroha::expected::resultToOptionalValue(
                 libp2p::multi::Multihash::createFromBuffer(
                     kagome::common::Buffer{pubKey.blob()}))) {
    if (opt_multihash->getType() == libp2p::multi::HashType::ed25519pub
        && opt_multihash->getHash().size()
            == shared_model::crypto::CryptoProviderEd25519Ursa::
                   kPublicKeyLength) {
      return CryptoProviderEd25519Ursa::verify(signedData, source, pubKey);
    }
  }

  return false;
}
