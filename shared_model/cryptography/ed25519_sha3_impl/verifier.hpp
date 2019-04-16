/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_VERIFIER_HPP
#define IROHA_SHARED_MODEL_VERIFIER_HPP

#include "cryptography/public_key.hpp"
#include "cryptography/signed.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * Class for signature verification.
     */
    class Verifier {
     public:
      static bool verify(const Signed &signedData,
                         const Blob &orig,
                         const PublicKey &publicKey);
    };

  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_VERIFIER_HPP
