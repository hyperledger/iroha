/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_subtract_asset_quantity.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    SubtractAssetQuantity::SubtractAssetQuantity(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          subtract_asset_quantity_{proto_->subtract_asset_quantity()},
          amount_{subtract_asset_quantity_.amount()} {}

    template SubtractAssetQuantity::SubtractAssetQuantity(
        SubtractAssetQuantity::TransportType &);
    template SubtractAssetQuantity::SubtractAssetQuantity(
        const SubtractAssetQuantity::TransportType &);
    template SubtractAssetQuantity::SubtractAssetQuantity(
        SubtractAssetQuantity::TransportType &&);

    SubtractAssetQuantity::SubtractAssetQuantity(const SubtractAssetQuantity &o)
        : SubtractAssetQuantity(o.proto_) {}

    SubtractAssetQuantity::SubtractAssetQuantity(
        SubtractAssetQuantity &&o) noexcept
        : SubtractAssetQuantity(std::move(o.proto_)) {}

    const interface::types::AssetIdType &SubtractAssetQuantity::assetId()
        const {
      return subtract_asset_quantity_.asset_id();
    }

    const interface::Amount &SubtractAssetQuantity::amount() const {
      return amount_;
    }

  }  // namespace proto
}  // namespace shared_model
