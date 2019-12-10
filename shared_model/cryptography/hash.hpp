/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_HASH_HPP
#define IROHA_SHARED_MODEL_HASH_HPP

#include "cryptography/bytes_wrapper.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * A special class for storing hashes. Main reason to introduce it is to
     * make difference between Hash which should represent a hashing result and
     * a generic Blob which should represent any binary data.
     */
    class Hash : public BytesWrapper {
     public:
      using BytesWrapper::BytesWrapper;

      std::string toString() const;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_HASH_HPP
