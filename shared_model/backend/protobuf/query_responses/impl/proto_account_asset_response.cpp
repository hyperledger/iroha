/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_account_asset_response.hpp"

namespace shared_model {
  namespace proto {

    AccountAssetResponse::AccountAssetResponse(
        iroha::protocol::QueryResponse &query_response)
        : account_asset_response_{query_response.account_assets_response()},
          account_assets_{query_response.mutable_account_assets_response()
                              ->mutable_account_assets()
                              ->begin(),
                          query_response.mutable_account_assets_response()
                              ->mutable_account_assets()
                              ->end()},
          next_asset_id_{[this]() -> decltype(next_asset_id_) {
            if (account_asset_response_.opt_next_asset_id_case()
                == iroha::protocol::AccountAssetResponse::kNextAssetId) {
              return this->account_asset_response_.next_asset_id();
            }
            return std::nullopt;
          }()} {}

    const interface::types::AccountAssetCollectionType
    AccountAssetResponse::accountAssets() const {
      return account_assets_;
    }

    std::optional<interface::types::AssetIdType>
    AccountAssetResponse::nextAssetId() const {
      return next_asset_id_;
    }

    size_t AccountAssetResponse::totalAccountAssetsNumber() const {
      return account_asset_response_.total_number();
    }

  }  // namespace proto
}  // namespace shared_model
