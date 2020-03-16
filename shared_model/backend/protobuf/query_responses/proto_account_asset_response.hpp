/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ACCOUNT_ASSET_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ACCOUNT_ASSET_RESPONSE_HPP

#include "interfaces/query_responses/account_asset_response.hpp"

#include "backend/protobuf/common_objects/account_asset.hpp"
#include "interfaces/common_objects/types.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class AccountAssetResponse final : public interface::AccountAssetResponse {
     public:
      explicit AccountAssetResponse(
          iroha::protocol::QueryResponse &query_response);

      const interface::types::AccountAssetCollectionType accountAssets()
          const override;

      std::optional<interface::types::AssetIdType> nextAssetId() const override;

      size_t totalAccountAssetsNumber() const override;

     private:
      const iroha::protocol::AccountAssetResponse &account_asset_response_;

      std::vector<AccountAsset> account_assets_;
      const std::optional<interface::types::AssetIdType> next_asset_id_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ACCOUNT_ASSET_RESPONSE_HPP
