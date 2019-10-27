/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/plain/common_objects/account_asset.hpp"

using namespace shared_model::interface::types;

using shared_model::plain::AccountAsset;

AccountAsset::AccountAsset(AccountIdType account_id,
                           AssetIdType asset_id,
                           shared_model::interface::Amount amount)
    : account_id_(std::move(account_id)),
      asset_id_(std::move(asset_id)),
      amount_(std::move(amount)) {}

const AccountIdType &AccountAsset::accountId() const {
  return account_id_;
}

const AssetIdType &AccountAsset::assetId() const {
  return asset_id_;
}

const shared_model::interface::Amount &AccountAsset::balance() const {
  return amount_;
}
