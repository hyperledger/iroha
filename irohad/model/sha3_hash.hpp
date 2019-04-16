/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef IROHA_SHA3_HASH_HPP
#define IROHA_SHA3_HASH_HPP

#include "crypto/hash_types.hpp"

namespace iroha {
  namespace model {
    struct Transaction;
    struct Block;
    struct Query;
  }  // namespace model

  hash256_t hash(const model::Transaction &tx);
  hash256_t hash(const model::Block &block);
  hash256_t hash(const model::Query &query);
}  // namespace iroha
#endif  // IROHA_SHA3_HASH_HPP
