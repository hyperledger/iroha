/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_SIGNATURES_HPP
#define IROHA_GET_SIGNATURES_HPP

#include <string>

#include "model/query.hpp"

namespace iroha {
  namespace model {

    /**
     * Query for getting all signatories attached to account
     */
    struct GetSignatories : Query {
      /**
       * Account identifier
       */
      std::string account_id{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_GET_SIGNATURES_HPP
