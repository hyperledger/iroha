/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_SIGNER_HPP
#define IROHA_CRYPTO_SIGNER_HPP

#include "cryptography/blob.hpp"
#include "cryptography/ed25519_sha3_impl/crypto_provider.hpp"
#include "cryptography/keypair.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * CryptoSigner - wrapper for generalization signing for different
     * cryptographic algorithms
     * @tparam Algorithm - cryptographic algorithm for singing
     */
    template <typename Algorithm = CryptoProviderEd25519Sha3>
    class CryptoSigner {
     public:
      /**
       * Generate signature for target data
       * @param blob - data for signing
       * @param keypair - (public, private) keys for signing
       * @return hex signature
       */
      static std::string sign(const Blob &blob, const Keypair &keypair) {
        return Algorithm::sign(blob, keypair);
      }

      /// close constructor for forbidding instantiation
      CryptoSigner() = delete;
    };
  }  // namespace crypto
}  // namespace shared_model
#endif  // IROHA_CRYPTO_SIGNER_HPP
