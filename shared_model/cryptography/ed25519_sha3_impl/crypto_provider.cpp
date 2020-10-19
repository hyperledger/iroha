/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"

#include "cryptography/ed25519_sha3_impl/internal/ed25519_impl.hpp"
#include "cryptography/ed25519_sha3_impl/signer.hpp"
#include "cryptography/ed25519_sha3_impl/verifier.hpp"

using namespace shared_model::interface::types;

namespace shared_model {
  namespace crypto {

    std::string CryptoProviderEd25519Sha3::sign(const Blob &blob,
                                                const Keypair &keypair) {
      return Signer::sign(blob, keypair);
    }

    bool CryptoProviderEd25519Sha3::verify(SignatureByteRangeView signature,
                                           const Blob &orig,
                                           PublicKeyByteRangeView public_key) {
      return Verifier::verify(signature, orig, public_key);
    }

    Seed CryptoProviderEd25519Sha3::generateSeed() {
      return Seed(iroha::create_seed().to_string());
    }

    Seed CryptoProviderEd25519Sha3::generateSeed(
        const std::string &passphrase) {
      return Seed(iroha::create_seed(passphrase).to_string());
    }

    Keypair CryptoProviderEd25519Sha3::generateKeypair() {
      return generateKeypair(generateSeed());
    }

    Keypair CryptoProviderEd25519Sha3::generateKeypair(const Seed &seed) {
      assert(seed.size() == kSeedLength);
      auto keypair = iroha::create_keypair(
          iroha::blob_t<kSeedLength>::from_raw(seed.blob().data()));
      return Keypair(PublicKeyHexStringView{keypair.pubkey.to_hexstring()},
                     PrivateKey(keypair.privkey.to_string()));
    }

    Keypair CryptoProviderEd25519Sha3::generateKeypair(const PrivateKey &key) {
      assert(key.size() == kPrivateKeyLength);
      auto keypair = iroha::create_keypair(
          iroha::blob_t<kPrivateKeyLength>::from_raw(key.blob().data()));
      return Keypair(PublicKeyHexStringView{keypair.pubkey.to_hexstring()},
                     key);
    }

    constexpr size_t CryptoProviderEd25519Sha3::kHashLength;
    constexpr size_t CryptoProviderEd25519Sha3::kPublicKeyLength;
    constexpr size_t CryptoProviderEd25519Sha3::kPrivateKeyLength;
    constexpr size_t CryptoProviderEd25519Sha3::kSignatureLength;
    constexpr size_t CryptoProviderEd25519Sha3::kSeedLength;
  }  // namespace crypto
}  // namespace shared_model
