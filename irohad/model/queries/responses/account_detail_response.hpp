/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ACCOUNT_DETAIL_RESPONSE_HPP
#define IROHA_ACCOUNT_DETAIL_RESPONSE_HPP

#include <string>
#include "model/query_response.hpp"

namespace iroha {
  namespace model {

    struct AccountDetailResponse : public QueryResponse {
      std::string detail{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_ACCOUNT_DETAIL_RESPONSE_HPP
