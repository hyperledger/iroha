/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/account_asset_response.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string AccountAssetResponse::toString() const {
      auto response =
          detail::PrettyStringBuilder().init("AccountAssetResponse");
      for (const auto &asset : accountAssets())
        response.append(asset.toString());
      return response.finalize();
    }

    bool AccountAssetResponse::operator==(const ModelType &rhs) const {
      return accountAssets() == rhs.accountAssets();
    }

  }  // namespace interface
}  // namespace shared_model
