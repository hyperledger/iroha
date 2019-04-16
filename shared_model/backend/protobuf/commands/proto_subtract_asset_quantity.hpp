/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SUBTRACT_ASSET_QUANTITY_HPP
#define IROHA_PROTO_SUBTRACT_ASSET_QUANTITY_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/subtract_asset_quantity.hpp"
#include "interfaces/common_objects/amount.hpp"

namespace shared_model {
  namespace proto {
    class SubtractAssetQuantity final
        : public CopyableProto<interface::SubtractAssetQuantity,
                               iroha::protocol::Command,
                               SubtractAssetQuantity> {
     public:
      template <typename CommandType>
      explicit SubtractAssetQuantity(CommandType &&command);

      SubtractAssetQuantity(const SubtractAssetQuantity &o);

      SubtractAssetQuantity(SubtractAssetQuantity &&o) noexcept;

      const interface::types::AssetIdType &assetId() const override;

      const interface::Amount &amount() const override;

     private:
      const iroha::protocol::SubtractAssetQuantity &subtract_asset_quantity_;

      const interface::Amount amount_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SUBTRACT_ASSET_QUANTITY_HPP
