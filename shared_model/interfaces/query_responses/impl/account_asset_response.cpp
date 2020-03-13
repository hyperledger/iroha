/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/account_asset_response.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string AccountAssetResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("AccountAssetResponse")
          .appendNamed("assets", accountAssets())
          .appendNamed("total assets number", totalAccountAssetsNumber())
          .appendNamed("next asset id", nextAssetId())
          .finalize();
    }

    bool AccountAssetResponse::operator==(const ModelType &rhs) const {
      return accountAssets() == rhs.accountAssets()
          and totalAccountAssetsNumber() == rhs.totalAccountAssetsNumber()
          and nextAssetId() == rhs.nextAssetId();
    }

  }  // namespace interface
}  // namespace shared_model
