/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"

#include "ursa_crypto.h"

using shared_model::interface::types::ByteRange;

namespace {
  ByteRange irohaToUrsaBuffer(const ByteRange buffer) {
    return ByteBuffer{(int64_t)buffer.size(),
                      static_cast<uint8_t *>(buffer.data())};
  }
}  // namespace

namespace shared_model {
  namespace crypto {
    Signed CryptoProviderEd25519Ursa::sign(const Blob &blob,
                                           const Keypair &keypair) {
      ByteBuffer signature;

      const ByteBuffer kMessage = {(int64_t)blob.blob().size(),
                                   const_cast<uint8_t *>(blob.blob().data())};

      const ByteBuffer kPrivateKey = {
          (int64_t)keypair.privateKey().blob().size(),
          const_cast<uint8_t *>(keypair.privateKey().blob().data())};

      ExternError err;

      if (!ursa_ed25519_sign(&kMessage, &kPrivateKey, &signature, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return Signed{""};
      }

      Signed result(
          {(const std::string::value_type *)signature.data, signature.len});

      ursa_ed25519_bytebuffer_free(signature);
      return result;
    }

    bool CryptoProviderEd25519Ursa::verify(const ByteRange &signed_data,
                                           const ByteRange &source,
                                           const ByteRange &public_key) {
      assert(signed_data.size() == kSignatureLength);
      assert(public_key.size() == kPublicKeyLength);

      ExternErkor err;

      const ByteBuffer kMessage = irohaToUrsaBuffer(source);
      const ByteBuffer kSignature = irohaToUrsaBuffer(signed_data);
      const ByteBuffer kPublicKey = irohaToUrsaBuffer(public_key);

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

      std::string multi_blob{(const std::string::value_type *)public_key.data,
                             public_key.len};

      auto mh_pubkey = *iroha::expected::resultToOptionalValue(
          libp2p::multi::Multihash::create(
              libp2p::multi::HashType::ed25519pub,
              kagome::common::Buffer{
                  std::vector<uint8_t>{multi_blob.begin(), multi_blob.end()}}));

      Keypair result(PublicKey(mh_pubkey.toBuffer().toVector()),
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

      const ByteBuffer kSeed = {(int64_t)seed.blob().size(),
                                const_cast<uint8_t *>(seed.blob().data())};

      ExternError err;

      if (!ursa_ed25519_keypair_from_seed(
              &kSeed, &public_key, &private_key, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return Keypair{PublicKey{""}, PrivateKey{""}};
      }

      std::string multi_blob{(const std::string::value_type *)public_key.data,
                             public_key.len};

      auto mh_pubkey = *iroha::expected::resultToOptionalValue(
          libp2p::multi::Multihash::create(
              libp2p::multi::HashType::ed25519pub,
              kagome::common::Buffer{
                  std::vector<uint8_t>{multi_blob.begin(), multi_blob.end()}}));

      Keypair result(PublicKey(mh_pubkey.toBuffer().toVector()),
                     PrivateKey(std::string(
                         (const std::string::value_type *)private_key.data,
                         private_key.len)));

      ursa_ed25519_bytebuffer_free(public_key);
      ursa_ed25519_bytebuffer_free(private_key);
      return result;
    }
  }  // namespace crypto
}  // namespace shared_model
