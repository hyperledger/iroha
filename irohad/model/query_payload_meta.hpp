/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_QUERY_PAYLOAD_META_HPP
#define IROHA_QUERY_PAYLOAD_META_HPP

#include <string>

#include "datetime/time.hpp"
#include "model/signature.hpp"

namespace iroha {
  namespace model {
    /**
     * This model represents user intent for reading ledger.
     * Concrete queries should extend this interface.
     */
    struct QueryPayloadMeta {
      /**
       * Account id of transaction creator.
       *
       */
      std::string creator_account_id{};

      /**
       * Creation timestamp
       *
       */
      ts64_t created_ts{};

      /**
       * Query counter
       */
      uint64_t query_counter{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_QUERY_PAYLOAD_META_HPP
