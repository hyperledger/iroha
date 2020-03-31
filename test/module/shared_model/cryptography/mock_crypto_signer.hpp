/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_CRYPTO_SIGNER_HPP
#define IROHA_MOCK_CRYPTO_SIGNER_HPP

#include "cryptography/crypto_provider/crypto_signer.hpp"

#include <gmock/gmock.h>

namespace shared_model {
  namespace crypto {

    class MockCryptoSigner : public CryptoSigner {
     public:
      MOCK_CONST_METHOD1(sign, std::string(const Blob &blob));
      MOCK_CONST_METHOD0(
          publicKey, shared_model::interface::types::PublicKeyHexStringView());
    };

  }  // namespace crypto
}  // namespace shared_model

#endif
