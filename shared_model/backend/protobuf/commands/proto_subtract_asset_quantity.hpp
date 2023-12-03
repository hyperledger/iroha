/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SUBTRACT_ASSET_QUANTITY_HPP
#define IROHA_PROTO_SUBTRACT_ASSET_QUANTITY_HPP

#include "interfaces/commands/subtract_asset_quantity.hpp"

#include "commands.pb.h"
#include "interfaces/common_objects/amount.hpp"

namespace shared_model {
  namespace proto {
    class SubtractAssetQuantity final
        : public interface::SubtractAssetQuantity {
     public:
      explicit SubtractAssetQuantity(iroha::protocol::Command &command);

      const interface::types::AssetIdType &assetId() const override;

      const interface::Amount &amount() const override;

      const std::string &description() const override;

     private:
      const iroha::protocol::SubtractAssetQuantity &subtract_asset_quantity_;

      const interface::Amount amount_;
      const std::string description_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SUBTRACT_ASSET_QUANTITY_HPP
