/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_add_asset_quantity.hpp"

namespace shared_model {
  namespace proto {

    AddAssetQuantity::AddAssetQuantity(iroha::protocol::Command &command)
        : add_asset_quantity_{command.add_asset_quantity()},
          amount_{add_asset_quantity_.amount()} {}

    const interface::types::AssetIdType &AddAssetQuantity::assetId() const {
      return add_asset_quantity_.asset_id();
    }

    const interface::Amount &AddAssetQuantity::amount() const {
      return amount_;
    }

    const std::string &AddAssetQuantity::description() const {
      return description_;
    }

  }  // namespace proto
}  // namespace shared_model
