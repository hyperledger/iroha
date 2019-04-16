/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_add_asset_quantity.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    AddAssetQuantity::AddAssetQuantity(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          add_asset_quantity_{proto_->add_asset_quantity()},
          amount_{add_asset_quantity_.amount()} {}

    // TODO 30/05/2018 andrei Reduce boilerplate code in variant classes
    template AddAssetQuantity::AddAssetQuantity(
        AddAssetQuantity::TransportType &);
    template AddAssetQuantity::AddAssetQuantity(
        const AddAssetQuantity::TransportType &);
    template AddAssetQuantity::AddAssetQuantity(
        AddAssetQuantity::TransportType &&);

    AddAssetQuantity::AddAssetQuantity(const AddAssetQuantity &o)
        : AddAssetQuantity(o.proto_) {}

    AddAssetQuantity::AddAssetQuantity(AddAssetQuantity &&o) noexcept
        : AddAssetQuantity(std::move(o.proto_)) {}

    const interface::types::AssetIdType &AddAssetQuantity::assetId() const {
      return add_asset_quantity_.asset_id();
    }

    const interface::Amount &AddAssetQuantity::amount() const {
      return amount_;
    }

  }  // namespace proto
}  // namespace shared_model
