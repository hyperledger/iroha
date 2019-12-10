/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"

#include "ursa_crypto.h"

namespace {
  ByteBuffer makeByteBuffer(const BytesView &blob) {
    return ByteBuffer{(int64_t)blob.size(), const_cast<uint8_t *>(blob.data())};
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
        return Signed{""};
      }

      Signed result(std::string((const std::string::value_type *)signature.data,
                                signature.len));

      ursa_ed25519_bytebuffer_free(signature);
      return result;
    }

    bool CryptoProviderEd25519Ursa::verify(const Signed &signed_data,
                                           const Blob &orig,
                                           const PublicKey &public_key) {
      ExternError err;

      const ByteBuffer kMessage = makeByteBuffer(orig.blob());

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
        return Keypair{PublicKey{""}, PrivateKey{""}};
      }

      Keypair result(PublicKey(std::string(
                         (const std::string::value_type *)public_key.data,
                         public_key.len)),
                     PrivateKey(std::string(
                         (const std::string::value_type *)private_key.data,
                         private_key.len)));

      ursa_ed25519_bytebuffer_free(public_key);
      ursa_ed25519_bytebuffer_free(private_key);
      return result;
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
        return Keypair{PublicKey{""}, PrivateKey{""}};
      }

      Keypair result(PublicKey(std::string(
                         (const std::string::value_type *)public_key.data,
                         public_key.len)),
                     PrivateKey(std::string(
                         (const std::string::value_type *)private_key.data,
                         private_key.len)));

      ursa_ed25519_bytebuffer_free(public_key);
      ursa_ed25519_bytebuffer_free(private_key);
      return result;
    }

    // Ursa provides functions for retrieving key lengths, but we use hardcoded
    // values
    const size_t CryptoProviderEd25519Ursa::kHashLength = 256 / 8;
    const size_t CryptoProviderEd25519Ursa::kPublicKeyLength = 256 / 8;
    const size_t CryptoProviderEd25519Ursa::kPrivateKeyLength = 512 / 8;
    const size_t CryptoProviderEd25519Ursa::kSignatureLength = 512 / 8;

  }  // namespace crypto
}  // namespace shared_model
