/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"

#include "common/hexutils.hpp"
#include "multihash/multihash.hpp"
#include "ursa_crypto.h"

using namespace std::literals;
using namespace shared_model::interface::types;

namespace {
  inline ByteBuffer irohaToUrsaBuffer(const ByteRange buffer) {
    return ByteBuffer{
        static_cast<int64_t>(buffer.size()),
        reinterpret_cast<uint8_t *>(const_cast<std::byte *>(buffer.data()))};
  }

  inline ByteRange ursaToIrohaBuffer(const ByteBuffer buffer) {
    assert(buffer.len > 0);
    return ByteRange{reinterpret_cast<std::byte *>(buffer.data),
                     static_cast<size_t>(buffer.len)};
  }
}  // namespace

namespace shared_model {
  namespace crypto {
    std::string CryptoProviderEd25519Ursa::sign(const Blob &blob,
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
        return {};
      }

      std::string hex_signature;
      iroha::bytestringToHexstringAppend(ursaToIrohaBuffer(signature),
                                         hex_signature);
      ursa_ed25519_bytebuffer_free(signature);
      return hex_signature;
    }

    bool CryptoProviderEd25519Ursa::verify(ByteRange signed_data,
                                           ByteRange source,
                                           ByteRange public_key) {
      ExternError err;

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
        return Keypair{PublicKeyHexStringView{""sv}, PrivateKey{""}};
      }

      std::string multihash_public_key;
      iroha::multihash::encodeHexAppend(iroha::multihash::Type::ed25519pub,
                                        ursaToIrohaBuffer(public_key),
                                        multihash_public_key);

      Keypair result(PublicKeyHexStringView{multihash_public_key},
                     PrivateKey{ursaToIrohaBuffer(private_key)});

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
        return Keypair{PublicKeyHexStringView{""sv}, PrivateKey{""}};
      }

      std::string multihash_public_key;
      iroha::multihash::encodeHexAppend(iroha::multihash::Type::ed25519pub,
                                        ursaToIrohaBuffer(public_key),
                                        multihash_public_key);

      Keypair result(PublicKeyHexStringView{multihash_public_key},
                     PrivateKey{ursaToIrohaBuffer(private_key)});

      ursa_ed25519_bytebuffer_free(public_key);
      ursa_ed25519_bytebuffer_free(private_key);
      return result;
    }

    Keypair CryptoProviderEd25519Ursa::generateKeypair(
        const PrivateKey &private_key) {
      ByteBuffer public_key;
      ByteBuffer ursa_private_key{
          (int64_t)private_key.blob().size(),
          const_cast<uint8_t *>(private_key.blob().data())};

      ExternError err;

      if (!ursa_ed25519_get_public_key(&ursa_private_key, &public_key, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return Keypair{PublicKeyHexStringView{""sv}, PrivateKey{""}};
      }

      std::string multihash_public_key;
      iroha::multihash::encodeHexAppend(iroha::multihash::Type::ed25519pub,
                                        ursaToIrohaBuffer(public_key),
                                        multihash_public_key);

      Keypair result(PublicKeyHexStringView{multihash_public_key}, private_key);

      ursa_ed25519_bytebuffer_free(public_key);
      return result;
    }
  }  // namespace crypto
}  // namespace shared_model
