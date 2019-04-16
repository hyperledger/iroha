/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ACCOUNT_RESPONSE_HPP
#define IROHA_ACCOUNT_RESPONSE_HPP

#include "model/account.hpp"
#include "model/query_response.hpp"

namespace iroha {
  namespace model {

    /**
     * Provide response with account
     */
    struct AccountResponse : public QueryResponse {
      /**
       * Attached account
       */
      Account account;

      /**
       * Account's roles
       */
      std::vector<std::string> roles;
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_ACCOUNT_RESPONSE_HPP
