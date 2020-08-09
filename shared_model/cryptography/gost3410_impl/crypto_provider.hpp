/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GOST_CRYPTO_PROVIDER_HPP
#define GOST_CRYPTO_PROVIDER_HPP

#include "cryptography/keypair.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

namespace shared_model::crypto {
  /**
   * Wrapper class for signing-related stuff.
   */
  class CryptoProviderGOST3410{
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
     * Generates new keypair
     * @return Keypair generated
     */
    static Keypair generateKeypair();

    static const char *kName;
    static constexpr size_t kHashLength = 256 / 8;
    static constexpr size_t kPublicKeyLength = 256 / 8;
    static constexpr size_t kPrivateKeyLength = 256 / 8;
    static constexpr size_t kSignatureLength = 512 / 8;
    static constexpr size_t kSeedLength = 256 / 8;
  };
} // namespace shared_model::crypto

#endif //GOST_CRYPTO_PROVIDER_HPP
