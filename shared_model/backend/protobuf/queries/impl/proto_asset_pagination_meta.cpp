/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_asset_pagination_meta.hpp"

namespace types = shared_model::interface::types;

using namespace shared_model::proto;

AssetPaginationMeta::AssetPaginationMeta(const TransportType &query)
    : TrivialProto(query) {}

AssetPaginationMeta::AssetPaginationMeta(TransportType &&query)
    : TrivialProto(std::move(query)) {}

AssetPaginationMeta::AssetPaginationMeta(const AssetPaginationMeta &o)
    : AssetPaginationMeta(*o.proto_) {}

AssetPaginationMeta::AssetPaginationMeta(AssetPaginationMeta &&o) noexcept
    : TrivialProto(std::move(*o.proto_)) {}

types::TransactionsNumberType AssetPaginationMeta::pageSize() const {
  return proto_->page_size();
}

boost::optional<types::AssetIdType> AssetPaginationMeta::firstAssetId() const {
  if (proto_->opt_first_asset_id_case()
      == TransportType::OptFirstAssetIdCase::OPT_FIRST_ASSET_ID_NOT_SET) {
    return boost::none;
  }
  return proto_->first_asset_id();
}
