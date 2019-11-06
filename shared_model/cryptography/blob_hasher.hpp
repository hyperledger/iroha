/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_BLOB_HASHER_HPP
#define IROHA_CRYPTO_BLOB_HASHER_HPP

#include <cstddef>

namespace shared_model {
  namespace crypto {
    class Blob;

    /**
     * Hashing of Blob object
     */
    class BlobHasher {
     public:
      std::size_t operator()(const Blob &blob) const;
    };

  }  // namespace crypto
}  // namespace shared_model

#endif
