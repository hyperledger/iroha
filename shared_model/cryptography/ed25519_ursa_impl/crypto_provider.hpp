/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_URSA_CRYPTOPROVIDER_HPP
#define IROHA_URSA_CRYPTOPROVIDER_HPP

#if !defined(USE_LIBURSA)
#error USE_LIBURSA must be defined
#endif

#include "cryptography/keypair.hpp"
#include "cryptography/private_key.hpp"
#include "cryptography/seed.hpp"
#include "interfaces/common_objects/byte_range.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Wrapper class for signing-related stuff.
     */
    class CryptoProviderEd25519Ursa {
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
       * @param signedData - data to verify
       * @param orig - original message
       * @param publicKey - public key
       * @return true if verify was OK or false otherwise
       */
      static bool verify(shared_model::interface::types::ByteRange signed_data,
                         shared_model::interface::types::ByteRange source,
                         shared_model::interface::types::ByteRange public_key);

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

      // Ursa provides functions for retrieving key lengths, but we use
      // hardcoded values
      static constexpr size_t kHashLength = 256 / 8;
      static constexpr size_t kPublicKeyLength = 256 / 8;
      static constexpr size_t kPrivateKeyLength = 512 / 8;
      static constexpr size_t kSignatureLength = 512 / 8;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_URSA_CRYPTOPROVIDER_HPP
