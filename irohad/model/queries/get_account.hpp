/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_ACCOUNT_HPP
#define IROHA_GET_ACCOUNT_HPP

#include <string>
#include "model/query.hpp"

namespace iroha {
  namespace model {

    /**
     * Query for getting account's metadata
     */
    struct GetAccount : Query {
      /**
       * Account identifier
       */
      std::string account_id{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_GET_ACCOUNT_HPP
