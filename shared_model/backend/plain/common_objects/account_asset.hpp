/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PLAIN_ACCOUNT_ASSET_HPP
#define IROHA_PLAIN_ACCOUNT_ASSET_HPP

#include "interfaces/common_objects/account_asset.hpp"

namespace shared_model {
  namespace plain {
    class AccountAsset : public shared_model::interface::AccountAsset {
     public:
      AccountAsset(shared_model::interface::types::AccountIdType account_id,
                   shared_model::interface::types::AssetIdType asset_id,
                   shared_model::interface::Amount amount);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::AssetIdType &assetId() const override;

      const interface::Amount &balance() const override;

     private:
      shared_model::interface::types::AccountIdType account_id_;
      shared_model::interface::types::AssetIdType asset_id_;
      shared_model::interface::Amount amount_;
    };
  }  // namespace plain
}  // namespace shared_model

#endif  // IROHA_PLAIN_ACCOUNT_ASSET_HPP
