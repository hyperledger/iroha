/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ACCOUNT_ASSETS_RESPONSE_HPP
#define IROHA_ACCOUNT_ASSETS_RESPONSE_HPP

#include <vector>
#include "model/account_asset.hpp"
#include "model/query_response.hpp"

namespace iroha {
  namespace model {

    struct AccountAssetResponse : public QueryResponse {
      std::vector<AccountAsset> acct_assets{};
    };
  }  // namespace model
}  // namespace iroha
#endif  // IROHA_ACCOUNT_ASSETS_RESPONSE_HPP
