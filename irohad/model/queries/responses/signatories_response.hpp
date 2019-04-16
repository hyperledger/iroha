/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SIGNATURES_RESPONSE_HPP
#define IROHA_SIGNATURES_RESPONSE_HPP

#include <vector>

#include "crypto/keypair.hpp"
#include "model/query_response.hpp"

namespace iroha {
  namespace model {

    /**
     * Provide response with signatories attached to the account
     */
    struct SignatoriesResponse : public QueryResponse {
      /**
       * Vector with all public keys attached to account
       */
      std::vector<pubkey_t> keys{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_SIGNATURES_RESPONSE_HPP
