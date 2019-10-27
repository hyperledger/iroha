/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PLAIN_ACCOUNT_ASSET_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PLAIN_ACCOUNT_ASSET_RESPONSE_HPP

#include "interfaces/query_responses/account_asset_response.hpp"

namespace shared_model {
  namespace plain {
    class AccountAssetResponse
        : public shared_model::interface::AccountAssetResponse {
     public:
      using AssetsHolder =
          std::vector<std::unique_ptr<shared_model::interface::AccountAsset>>;

      AccountAssetResponse(
          AssetsHolder assets_page,
          boost::optional<shared_model::interface::types::AssetIdType>
              next_asset_id,
          size_t total_number);

      const shared_model::interface::types::AccountAssetCollectionType
      accountAssets() const override;

      boost::optional<shared_model::interface::types::AssetIdType> nextAssetId()
          const override;

      size_t totalAccountAssetsNumber() const override;

     private:
      AssetsHolder assets_page_;
      boost::optional<shared_model::interface::types::AssetIdType>
          next_asset_id_;
      size_t total_number_;
    };

  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PLAIN_ACCOUNT_ASSET_RESPONSE_HPP
