/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_RESPONSE_HPP
#define IROHA_QUERY_RESPONSE_HPP

#include <memory>

#include "crypto/hash_types.hpp"
#include "model/client.hpp"
#include "model/query.hpp"

namespace iroha {
  namespace model {
    /**
     * Interface of query response for user
     */
    struct QueryResponse {
      /**
       * Client query
       */
      hash256_t query_hash{};

      virtual ~QueryResponse() {}
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_QUERY_RESPONSE_HPP
