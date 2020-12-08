/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PRIVATE_KEY_HPP
#define IROHA_SHARED_MODEL_PRIVATE_KEY_HPP

#include "cryptography/blob.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * A special class for storing private keys.
     */
    class PrivateKey : public Blob {
     public:
      using Blob::Blob;

      explicit PrivateKey(const Blob &blob);

      std::string toString() const override;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PRIVATE_KEY_HPP
