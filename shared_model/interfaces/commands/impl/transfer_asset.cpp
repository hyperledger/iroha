/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/transfer_asset.hpp"

namespace shared_model {
  namespace interface {

    std::string TransferAsset::toString() const {
      return detail::PrettyStringBuilder()
          .init("TransferAsset")
          .appendNamed("src_account_id", srcAccountId())
          .appendNamed("dest_account_id", destAccountId())
          .appendNamed("asset_id", assetId())
          .appendNamed("description", description())
          .appendNamed("amount", amount())
          .finalize();
    }

    bool TransferAsset::operator==(const ModelType &rhs) const {
      return srcAccountId() == rhs.srcAccountId()
          and destAccountId() == rhs.destAccountId()
          and assetId() == rhs.assetId() and amount() == rhs.amount()
          and description() == rhs.description();
    }

  }  // namespace interface
}  // namespace shared_model
