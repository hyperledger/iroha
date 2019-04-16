/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_transfer_asset.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    TransferAsset::TransferAsset(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          transfer_asset_{proto_->transfer_asset()},
          amount_{transfer_asset_.amount()} {}

    template TransferAsset::TransferAsset(TransferAsset::TransportType &);
    template TransferAsset::TransferAsset(const TransferAsset::TransportType &);
    template TransferAsset::TransferAsset(TransferAsset::TransportType &&);

    TransferAsset::TransferAsset(const TransferAsset &o)
        : TransferAsset(o.proto_) {}

    TransferAsset::TransferAsset(TransferAsset &&o) noexcept
        : TransferAsset(std::move(o.proto_)) {}

    const interface::Amount &TransferAsset::amount() const {
      return amount_;
    }

    const interface::types::AssetIdType &TransferAsset::assetId() const {
      return transfer_asset_.asset_id();
    }

    const interface::types::AccountIdType &TransferAsset::srcAccountId() const {
      return transfer_asset_.src_account_id();
    }

    const interface::types::AccountIdType &TransferAsset::destAccountId()
        const {
      return transfer_asset_.dest_account_id();
    }

    const interface::types::DescriptionType &TransferAsset::description()
        const {
      return transfer_asset_.description();
    }

  }  // namespace proto
}  // namespace shared_model
