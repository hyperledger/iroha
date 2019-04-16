/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ACCOUNT_HPP
#define IROHA_ACCOUNT_HPP

#include <string>

namespace iroha {
  namespace model {

    /**
     * Account Model
     */
    struct Account {
      /**
       * User name is used as unique identifier of an account
       */
      std::string account_id;

      /**
       * Account has only one domain.
       * Id of the domain of a account
       */
      std::string domain_id;

      /**
       * Minimum quorum of signatures need for transactions
       */
      uint32_t quorum;

      /**
       * Key/Value account data
       */
      std::string json_data;

      Account() {}
    };
  }  // namespace model
}  // namespace iroha

#endif  // IROHA_ACCOUNT_HPP
