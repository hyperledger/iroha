/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_TEST_CRYPTO_VERIFIER
#define IROHA_TEST_CRYPTO_VERIFIER

#include <memory>

#include "cryptography/crypto_provider/crypto_verifier.hpp"
#include "module/shared_model/cryptography/mock_crypto_verifier.hpp"

namespace iroha {
  namespace test {

    static inline std::shared_ptr<shared_model::crypto::CryptoVerifier>
    getTestCryptoVerifier() {
      static std::shared_ptr<shared_model::crypto::CryptoVerifier> verifier{
          std::make_shared<shared_model::crypto::CryptoVerifier>()};
      return verifier;
    }

    static inline std::shared_ptr<shared_model::crypto::CryptoVerifier>
    getMockCryptoVerifier() {
      static std::shared_ptr<shared_model::crypto::CryptoVerifier> verifier{
          std::make_shared<shared_model::crypto::MockCryptoVerifier>()};
      return verifier;
    }

  }  // namespace test
}  // namespace iroha

#endif
