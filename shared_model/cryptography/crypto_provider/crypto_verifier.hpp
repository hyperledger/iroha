/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_VERIFIER_HPP
#define IROHA_CRYPTO_VERIFIER_HPP

#include "common/result_fwd.hpp"
#include "interfaces/common_objects/string_view_types.hpp"

namespace shared_model {
  namespace crypto {
    class Blob;

    /**
     * CryptoVerifier - adapter for generalization verification of cryptographic
     * signatures
     * @tparam Algorithm - cryptographic algorithm for verification
     */
    class CryptoVerifier {
     public:
      /**
       * Verify signature attached to source data
       * @param signedData - cryptographic signature
       * @param source - data that was signed
       * @param pubKey - public key of signatory
       * @return a result of void if signature is correct or error message
       * otherwise or if verification could not be completed
       */
      static iroha::expected::Result<void, const char *> verify(
          shared_model::interface::types::SignedHexStringView signature,
          const Blob &source,
          shared_model::interface::types::PublicKeyHexStringView public_key);

      /// close constructor for forbidding instantiation
      CryptoVerifier() = delete;

      enum { kMaxPublicKeySize = 68 };
      enum { kMaxSignatureSize = 68 };
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_CRYPTO_VERIFIER_HPP
