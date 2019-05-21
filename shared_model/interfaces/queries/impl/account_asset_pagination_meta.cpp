/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/queries/account_asset_pagination_meta.hpp"

using namespace shared_model::interface;

bool AccountAssetPaginationMeta::operator==(const ModelType &rhs) const {
  return pageSize() == rhs.pageSize() and firstAssetId() == rhs.firstAssetId();
}

std::string AccountAssetPaginationMeta::toString() const {
  return detail::PrettyStringBuilder()
      .init("AccountAssetPaginationMeta")
      .append("page_size", std::to_string(pageSize()))
      .append("first_asset_id", firstAssetId().value_or("(none)"))
      .finalize();
}
