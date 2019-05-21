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
          .appendAll(
              "assets", accountAssets(), [](auto &tx) { return tx.toString(); })
          .append("total assets number",
                  std::to_string(totalAccountAssetsNumber()))
          .append("next asset id", nextAssetId().value_or("(none)"))
          .finalize();
    }

    bool AccountAssetResponse::operator==(const ModelType &rhs) const {
      return accountAssets() == rhs.accountAssets()
          and totalAccountAssetsNumber() == rhs.totalAccountAssetsNumber()
          and nextAssetId() == rhs.nextAssetId();
    }

  }  // namespace interface
}  // namespace shared_model
