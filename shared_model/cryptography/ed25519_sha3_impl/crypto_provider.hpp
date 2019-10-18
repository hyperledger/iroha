/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTOPROVIDER_HPP
#define IROHA_CRYPTOPROVIDER_HPP

#include "cryptography/keypair.hpp"
#include "cryptography/seed.hpp"
#include "cryptography/signed.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Wrapper class for signing-related stuff.
     */
    class CryptoProviderEd25519Sha3 {
     public:
      /**
       * Signs the message.
       * @param blob - blob to sign
       * @param keypair - keypair
       * @return Signed object with signed data
       */
      static Signed sign(const Blob &blob, const Keypair &keypair);

      /**
       * Verifies signature.
       * @param signedData - data to verify
       * @param orig - original message
       * @param publicKey - public key
       * @return true if verify was OK or false otherwise
       */
      static bool verify(const Signed &signedData,
                         const Blob &orig,
                         const PublicKey &publicKey);
      /**
       * Generates new seed
       * @return Seed generated
       */
      static Seed generateSeed();

      /**
       * Generates new seed from a provided passphrase
       * @param passphrase - passphrase to generate seed from
       * @return Seed generated
       */
      static Seed generateSeed(const std::string &passphrase);

      /**
       * Generates new keypair with a default seed
       * @return Keypair generated
       */
      static Keypair generateKeypair();

      /**
       * Generates new keypair from a provided seed
       * @param seed - provided seed
       * @return generated keypair
       */
      static Keypair generateKeypair(const Seed &seed);

      static constexpr size_t kHashLength = 256 / 8;
      static constexpr size_t kPublicKeyLength = 256 / 8;
      static constexpr size_t kPrivateKeyLength = 256 / 8;
      static constexpr size_t kSignatureLength = 512 / 8;
      static constexpr size_t kSeedLength = 256 / 8;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_CRYPTOPROVIDER_HPP
