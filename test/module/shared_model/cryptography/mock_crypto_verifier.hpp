/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_CRYPTO_VERIFIER_HPP
#define IROHA_MOCK_CRYPTO_VERIFIER_HPP

#include "cryptography/crypto_provider/crypto_verifier.hpp"

#include <gmock/gmock.h>
#include "common/result.hpp"

namespace shared_model {
  namespace crypto {

    class MockCryptoVerifier : public CryptoVerifier {
     public:
      MockCryptoVerifier() {
        using namespace testing;
        ON_CALL(*this, verify(_, _, _))
            .WillByDefault(Return(iroha::expected::Value<void>{}));
      }

      MOCK_CONST_METHOD3(
          verify,
          iroha::expected::Result<void, const char *>(
              const shared_model::interface::types::SignedHexStringView
                  &signature,
              const Blob &source,
              shared_model::interface::types::PublicKeyHexStringView
                  public_key));
    };

  }  // namespace crypto
}  // namespace shared_model

#endif
