/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTOPROVIDER_HPP
#define IROHA_CRYPTOPROVIDER_HPP

#include "cryptography/keypair.hpp"
#include "cryptography/seed.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

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
       * @return hex signature data string
       */
      static std::string sign(const Blob &blob, const Keypair &keypair);

      /**
       * Verifies signature.
       * @param signature - data to verify
       * @param orig - original message
       * @param public_key - public key
       * @return true if verify was OK or false otherwise
       */
      static bool verify(
          shared_model::interface::types::SignatureByteRangeView signature,
          const Blob &orig,
          shared_model::interface::types::PublicKeyByteRangeView public_key);
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

      /**
       * Generates new keypair from a provided private key
       * @param key - private key for the new keypair
       * @return generated keypair
       */
      static Keypair generateKeypair(const PrivateKey &key);

      static constexpr size_t kHashLength = 256 / 8;
      static constexpr size_t kPublicKeyLength = 256 / 8;
      static constexpr size_t kPrivateKeyLength = 256 / 8;
      static constexpr size_t kSignatureLength = 512 / 8;
      static constexpr size_t kSeedLength = 256 / 8;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_CRYPTOPROVIDER_HPP
