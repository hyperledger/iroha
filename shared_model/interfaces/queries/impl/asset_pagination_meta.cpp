/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/asset_pagination_meta.hpp"

using namespace shared_model::interface;

bool AssetPaginationMeta::operator==(const ModelType &rhs) const {
  return pageSize() == rhs.pageSize() and firstAssetId() == rhs.firstAssetId();
}

std::string AssetPaginationMeta::toString() const {
  return detail::PrettyStringBuilder()
      .init("AssetPaginationMeta")
      .appendNamed("page_size", pageSize())
      .appendNamed("first_asset_id", firstAssetId())
      .finalize();
}
