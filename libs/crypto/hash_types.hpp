/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CRYPTO_HASH_TYPES_HPP
#define IROHA_CRYPTO_HASH_TYPES_HPP

#include "common/blob.hpp"

namespace iroha {

  template <size_t size>
  using hash_t = blob_t<size>;

  // fixed-size hashes
  using hash224_t = hash_t<224 / 8>;
  using hash256_t = hash_t<256 / 8>;
  using hash384_t = hash_t<384 / 8>;
  using hash512_t = hash_t<512 / 8>;

  template <typename HashType>
  using HashView = FixedBlobView<HashType::size()>;
  using Hash224View = HashView<hash224_t>;
  using Hash256View = HashView<hash256_t>;
  using Hash384View = HashView<hash384_t>;
  using Hash512View = HashView<hash512_t>;

}  // namespace iroha
#endif  // IROHA_CRYPTO_HASH_TYPES_HPP
