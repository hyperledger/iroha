/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_asset_pagination_meta.hpp"

#include <optional>

namespace types = shared_model::interface::types;

using namespace shared_model::proto;

AssetPaginationMeta::AssetPaginationMeta(
    iroha::protocol::AssetPaginationMeta &meta)
    : meta_{meta} {}

types::TransactionsNumberType AssetPaginationMeta::pageSize() const {
  return meta_.page_size();
}

std::optional<types::AssetIdType> AssetPaginationMeta::firstAssetId() const {
  if (meta_.opt_first_asset_id_case()
      == iroha::protocol::AssetPaginationMeta::OptFirstAssetIdCase::
             OPT_FIRST_ASSET_ID_NOT_SET) {
    return std::nullopt;
  }
  return meta_.first_asset_id();
}
