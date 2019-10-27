/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/query_responses/account_asset_response.hpp"

#include <boost/range/adaptor/indirected.hpp>

using shared_model::plain::AccountAssetResponse;

AccountAssetResponse::AccountAssetResponse(
    AssetsHolder assets_page,
    boost::optional<shared_model::interface::types::AssetIdType> next_asset_id,
    size_t total_number)
    : assets_page_(std::move(assets_page)),
      next_asset_id_(std::move(next_asset_id)),
      total_number_(total_number) {}

const shared_model::interface::types::AccountAssetCollectionType
AccountAssetResponse::accountAssets() const {
  return assets_page_ | boost::adaptors::indirected;
}

boost::optional<shared_model::interface::types::AssetIdType>
AccountAssetResponse::nextAssetId() const {
  return next_asset_id_;
}

size_t AccountAssetResponse::totalAccountAssetsNumber() const {
  return total_number_;
}
