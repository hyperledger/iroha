/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_SIGNER_HPP
#define IROHA_CRYPTO_SIGNER_HPP

#include <string>

namespace shared_model {
  namespace crypto {

    class Blob;
    class Keypair;

    /**
     * CryptoSigner - wrapper for generalization signing for different
     * cryptographic algorithms
     * @tparam Algorithm - cryptographic algorithm for singing
     */
    class CryptoSigner {
     public:
      /**
       * Generate signature for target data
       * @param blob - data for signing
       * @param keypair - (public, private) keys for signing
       * @return hex signature
       */
      static std::string sign(const Blob &blob, const Keypair &keypair);

      /// close constructor for forbidding instantiation
      CryptoSigner() = delete;
    };
  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_CRYPTO_SIGNER_HPP
