/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_HASH_HPP
#define IROHA_SHARED_MODEL_HASH_HPP

#include "cryptography/blob.hpp"

namespace shared_model {
  namespace crypto {
    /**
     * A special class for storing hashes. Main reason to introduce it is to
     * make difference between Hash which should represent a hashing result and
     * a generic Blob which should represent any binary data.
     */
    class Hash : public Blob {
     public:
      /**
       * To calculate hash used by some standard containers
       */
      struct Hasher {
        std::size_t operator()(Hash const &h) const;
      };

      Hash();

      explicit Hash(const std::string &hash);
      explicit Hash(std::string_view hash);
      explicit Hash(const char *hash);

      explicit Hash(const Blob &blob);

      /**
       * Creates new Hash object from provided hex string
       * @param hex - string in hex format to create Hash from
       * @return Hash from provided hex string if it was correct or
       * Hash from empty string if provided string was not a correct hex string
       */
      static Hash fromHexString(const std::string &hex);

      std::string toString() const override;
    };
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_HASH_HPP
