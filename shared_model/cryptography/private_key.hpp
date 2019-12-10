/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PRIVATE_KEY_HPP
#define IROHA_SHARED_MODEL_PRIVATE_KEY_HPP

#include "cryptography/bytes_wrapper.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * A special class for storing private keys.
     */
    class PrivateKey : public BytesWrapper {
     public:
      using BytesWrapper::BytesWrapper;

      std::string toString() const;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PRIVATE_KEY_HPP
