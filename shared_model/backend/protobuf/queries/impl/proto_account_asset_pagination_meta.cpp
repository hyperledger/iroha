/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_account_asset_pagination_meta.hpp"

namespace types = shared_model::interface::types;

using namespace shared_model::proto;

AccountAssetPaginationMeta::AccountAssetPaginationMeta(
    const TransportType &query)
    : CopyableProto(query) {}

AccountAssetPaginationMeta::AccountAssetPaginationMeta(TransportType &&query)
    : CopyableProto(std::move(query)) {}

AccountAssetPaginationMeta::AccountAssetPaginationMeta(
    const AccountAssetPaginationMeta &o)
    : AccountAssetPaginationMeta(*o.proto_) {}

AccountAssetPaginationMeta::AccountAssetPaginationMeta(
    AccountAssetPaginationMeta &&o) noexcept
    : CopyableProto(std::move(*o.proto_)) {}

types::TransactionsNumberType AccountAssetPaginationMeta::pageSize() const {
  return proto_->page_size();
}

boost::optional<types::AssetIdType> AccountAssetPaginationMeta::firstAssetId()
    const {
  if (proto_->opt_first_asset_id_case()
      == TransportType::OptFirstAssetIdCase::OPT_FIRST_ASSET_ID_NOT_SET) {
    return boost::none;
  }
  return proto_->first_asset_id();
}
