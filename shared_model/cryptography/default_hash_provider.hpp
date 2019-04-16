/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_DEFAULT_HASH_PROVIDER_HPP
#define IROHA_DEFAULT_HASH_PROVIDER_HPP

#include "cryptography/hash_providers/sha3_256.hpp"

namespace shared_model {
  namespace crypto {
    // Default class that provides hashing functionality
    using DefaultHashProvider = shared_model::crypto::Sha3_256;
  }  // namespace crypto
}  // namespace shared_model

#endif  // IROHA_DEFAULT_HASH_PROVIDER_HPP
