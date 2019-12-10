/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_VERIFIER_HPP
#define IROHA_CRYPTO_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_defaults.hpp"

namespace shared_model {
  namespace crypto {
    class Signed;
    class BytesView;
    class PublicKey;

    /**
     * CryptoVerifier - adapter for generalization verification of cryptographic
     * signatures
     * @tparam Algorithm - cryptographic algorithm for verification
     */
    template <typename Algorithm = DefaultCryptoAlgorithmType>
    class CryptoVerifier {
     public:
      /**
       * Verify signature attached to source data
       * @param signedData - cryptographic signature
       * @param source - data that was signed
       * @param pubKey - public key of signatory
       * @return true if signature correct
       */
      static bool verify(const Signed &signedData,
                         const BytesView &source,
                         const PublicKey &pubKey) {
        return Algorithm::verify(signedData, source, pubKey);
      }

      /// close constructor for forbidding instantiation
      CryptoVerifier() = delete;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_CRYPTO_VERIFIER_HPP
