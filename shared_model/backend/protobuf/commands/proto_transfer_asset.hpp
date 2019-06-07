/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_TRANSFER_ASSET_HPP
#define IROHA_PROTO_TRANSFER_ASSET_HPP

#include "interfaces/commands/transfer_asset.hpp"

#include "commands.pb.h"
#include "interfaces/common_objects/amount.hpp"

namespace shared_model {
  namespace proto {

    class TransferAsset final : public interface::TransferAsset {
     public:
      explicit TransferAsset(iroha::protocol::Command &command);

      const interface::Amount &amount() const override;

      const interface::types::AssetIdType &assetId() const override;

      const interface::types::AccountIdType &srcAccountId() const override;

      const interface::types::AccountIdType &destAccountId() const override;

      const interface::types::DescriptionType &description() const override;

     private:
      const iroha::protocol::TransferAsset &transfer_asset_;

      const interface::Amount amount_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_TRANSFER_ASSET_HPP
