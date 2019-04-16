/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_ABSTRACT_CRYPTO_MODEL_SIGNER_HPP
#define IROHA_MOCK_ABSTRACT_CRYPTO_MODEL_SIGNER_HPP

#include "cryptography/crypto_provider/abstract_crypto_model_signer.hpp"

#include <gmock/gmock.h>

namespace shared_model {
  namespace crypto {

    template <typename T>
    class MockAbstractCryptoModelSigner : public AbstractCryptoModelSigner<T> {
     public:
      MOCK_CONST_METHOD1_T(sign, void(T &));
    };

  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_MOCK_ABSTRACT_CRYPTO_MODEL_SIGNER_HPP
