/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"

#include "cryptography/ed25519_ursa_impl/ursa_blob.hpp"
#include "ursa_crypto.h"

namespace {
  ByteBuffer makeByteBuffer(const shared_model::crypto::BytesView &blob) {
    return ByteBuffer{(int64_t)blob.size(), const_cast<uint8_t *>(blob.data())};
  }

  std::unique_ptr<shared_model::crypto::BytesView> makeBlob(
      const ByteBuffer &buf) {
    return std::make_unique<shared_model::crypto::UrsaBlob>(buf);
  }
}  // namespace

namespace shared_model {
  namespace crypto {
    Signed CryptoProviderEd25519Ursa::sign(const BytesView &blob,
                                           const Keypair &keypair) {
      ByteBuffer signature;

      const ByteBuffer kMessage = makeByteBuffer(blob);

      const ByteBuffer kPrivateKey =
          makeByteBuffer(keypair.privateKey().blob());

      ExternError err;

      if (!ursa_ed25519_sign(&kMessage, &kPrivateKey, &signature, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return Signed{nullptr};  // very bad
      }

      return Signed{makeBlob(signature)};
    }

    bool CryptoProviderEd25519Ursa::verify(const Signed &signed_data,
                                           const BytesView &orig,
                                           const PublicKey &public_key) {
      ExternError err;

      const ByteBuffer kMessage = makeByteBuffer(orig);

      const ByteBuffer kSignature = makeByteBuffer(signed_data.blob());

      const ByteBuffer kPublicKey = makeByteBuffer(public_key.blob());

      if (!ursa_ed25519_verify(&kMessage, &kSignature, &kPublicKey, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return false;
      } else {
        return true;
      }
    }

    Keypair CryptoProviderEd25519Ursa::generateKeypair() {
      ByteBuffer public_key;
      ByteBuffer private_key;
      ExternError err;

      if (!ursa_ed25519_keypair_new(&public_key, &private_key, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return Keypair{PublicKey{nullptr}, PrivateKey{nullptr}};  // very bad
      }

      return Keypair{PublicKey{makeBlob(public_key)},
                     PrivateKey{makeBlob(private_key)}};
    }

    Keypair CryptoProviderEd25519Ursa::generateKeypair(const Seed &seed) {
      ByteBuffer public_key;
      ByteBuffer private_key;

      const ByteBuffer kSeed = makeByteBuffer(seed.blob());

      ExternError err;

      if (!ursa_ed25519_keypair_from_seed(
              &kSeed, &public_key, &private_key, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return Keypair{PublicKey{nullptr}, PrivateKey{nullptr}};  // very bad
      }

      return Keypair{PublicKey{makeBlob(public_key)},
                     PrivateKey{makeBlob(private_key)}};
    }

    // Ursa provides functions for retrieving key lengths, but we use hardcoded
    // values
    const size_t CryptoProviderEd25519Ursa::kHashLength = 256 / 8;
    const size_t CryptoProviderEd25519Ursa::kPublicKeyLength = 256 / 8;
    const size_t CryptoProviderEd25519Ursa::kPrivateKeyLength = 512 / 8;
    const size_t CryptoProviderEd25519Ursa::kSignatureLength = 512 / 8;

  }  // namespace crypto
}  // namespace shared_model
