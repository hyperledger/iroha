/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "cryptography/ed25519_ursa_impl/crypto_provider.hpp"

#include "common/hexutils.hpp"
#include "cryptography/ed25519_ursa_impl/common.hpp"
#include "multihash/multihash.hpp"
#include "ursa_crypto.h"

using namespace std::literals;
using namespace shared_model::crypto::ursa;
using namespace shared_model::interface::types;

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

    Keypair CryptoProviderEd25519Ursa::generateKeypair() {
      ByteBuffer public_key;
      ByteBuffer private_key;
      ExternError err;

      if (!ursa_ed25519_keypair_new(&public_key, &private_key, &err)) {
        // handle error
        ursa_ed25519_string_free(err.message);
        return Keypair{PublicKeyHexStringView{""sv}, PrivateKey{""}};
      }

      std::string multuhash_public_key;
      iroha::multihash::encodeBinAppend(
          iroha::multihash::Type::ed25519_sha2_256,
          ursaToIrohaBuffer(public_key),
          multuhash_public_key);

      Keypair result(PublicKeyHexStringView{multuhash_public_key},
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

      std::string multuhash_public_key;
      iroha::multihash::encodeBinAppend(
          iroha::multihash::Type::ed25519_sha2_256,
          ursaToIrohaBuffer(public_key),
          multuhash_public_key);

      Keypair result(PublicKeyHexStringView{multuhash_public_key},
                     PrivateKey{ursaToIrohaBuffer(private_key)});

      ursa_ed25519_bytebuffer_free(public_key);
      ursa_ed25519_bytebuffer_free(private_key);
      return result;
    }

    const char *CryptoProviderEd25519Ursa::kName = "Internal Ed25519 with Ursa";
  }  // namespace crypto
}  // namespace shared_model
