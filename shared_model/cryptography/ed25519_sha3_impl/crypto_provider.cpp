/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"

#include "cryptography/bytes_view.hpp"
#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/signer.hpp"
#include "cryptography/ed25519_sha3_impl/verifier.hpp"

namespace shared_model {
  namespace crypto {

    Signed CryptoProviderEd25519Sha3::sign(const BytesView &blob,
                                           const Keypair &keypair) {
      return Signer::sign(blob, keypair);
    }

    bool CryptoProviderEd25519Sha3::verify(const Signed &signedData,
                                           const BytesView &orig,
                                           const PublicKey &publicKey) {
      return Verifier::verify(signedData, orig, publicKey);
    }

    Seed CryptoProviderEd25519Sha3::generateSeed() {
      return Seed{std::make_shared<shared_model::crypto::Blob>(
          iroha::create_seed().getView().byteRange())};
    }

    Keypair CryptoProviderEd25519Sha3::generateKeypair() {
      return generateKeypair(generateSeed());
    }

    Keypair CryptoProviderEd25519Sha3::generateKeypair(const Seed &seed) {
      assert(seed.blob().size() == kSeedLength);
      static_assert(kSeedLength == 32,
                    "Incompatible seed length");  // 32 comes from
                                                  // iroha::create_keypair(...)
      auto keypair = iroha::create_keypair(
          iroha::blob_t<32>::from_raw(seed.blob().byteRange().begin()));
      return Keypair{PublicKey(std::make_shared<shared_model::crypto::Blob>(
                         keypair.pubkey.getView().byteRange())),
                     PrivateKey(std::make_shared<shared_model::crypto::Blob>(
                         keypair.privkey.getView().byteRange()))};
    }
  }  // namespace crypto
}  // namespace shared_model
