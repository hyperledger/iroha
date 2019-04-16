/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_ACCOUNT_DETAIL_HPP
#define IROHA_GET_ACCOUNT_DETAIL_HPP

#include <string>
#include "model/query.hpp"

namespace iroha {
  namespace model {
    /**
     * Query for get all account's detail
     */
    struct GetAccountDetail : Query {
      std::string account_id{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_GET_ACCOUNT_DETAIL_HPP
