/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_SIGNER_HPP
#define IROHA_CRYPTO_SIGNER_HPP

#include "interfaces/common_objects/string_view_types.hpp"

namespace shared_model {
  namespace crypto {
    class Blob;
    class Signed;

    /**
     * CryptoSigner - wrapper for generalization signing for different
     * cryptographic algorithms
     */
    class CryptoSigner {
     public:
      virtual ~CryptoSigner() = default;

      /**
       * Generate signature for target data
       * @param blob - data for signing
       * @param keypair - (public, private) keys for signing
       * @return signature's blob
       */
      virtual std::string sign(const Blob &blob) const = 0;

      /// Get public key.
      virtual shared_model::interface::types::PublicKeyHexStringView publicKey()
          const = 0;
    };
  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_CRYPTO_SIGNER_HPP
