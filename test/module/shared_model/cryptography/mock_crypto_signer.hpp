/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_CRYPTO_SIGNER_HPP
#define IROHA_MOCK_CRYPTO_SIGNER_HPP

#include "cryptography/crypto_provider/crypto_signer.hpp"

#include <gmock/gmock.h>
#include "framework/crypto_literals.hpp"

namespace shared_model {
  namespace crypto {

    class MockCryptoSigner : public CryptoSigner {
     public:
      MockCryptoSigner() {
        using namespace testing;
        ON_CALL(*this, sign(_)).WillByDefault(Return(""));
        ON_CALL(*this, publicKey()).WillByDefault(Return(""_hex_pubkey));
      }

      MOCK_CONST_METHOD1(sign, std::string(const Blob &blob));
      MOCK_CONST_METHOD0(
          publicKey, shared_model::interface::types::PublicKeyHexStringView());

      std::string toString() const override {
        return "MockCryptoSigner";
      }
    };

  }  // namespace crypto
}  // namespace shared_model

#endif
