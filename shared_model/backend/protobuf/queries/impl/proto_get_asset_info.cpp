/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_asset_info.hpp"

namespace shared_model {
  namespace proto {

    GetAssetInfo::GetAssetInfo(iroha::protocol::Query &query)
        : asset_info_{query.payload().get_asset_info()} {}

    const interface::types::AssetIdType &GetAssetInfo::assetId() const {
      return asset_info_.asset_id();
    }

  }  // namespace proto
}  // namespace shared_model
