/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ACCOUNT_ASSET_HPP
#define IROHA_PROTO_ACCOUNT_ASSET_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/util.hpp"
#include "interfaces/common_objects/account_asset.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class AccountAsset final
        : public TrivialProto<interface::AccountAsset,
                              iroha::protocol::AccountAsset> {
     public:
      template <typename AccountAssetType>
      explicit AccountAsset(AccountAssetType &&accountAssetType)
          : TrivialProto(std::forward<AccountAssetType>(accountAssetType)) {}

      AccountAsset(const AccountAsset &o) : AccountAsset(o.proto_) {}

      AccountAsset(AccountAsset &&o) noexcept
          : AccountAsset(std::move(o.proto_)) {}

      const interface::types::AccountIdType &accountId() const override {
        return proto_->account_id();
      }

      const interface::types::AssetIdType &assetId() const override {
        return proto_->asset_id();
      }

      const interface::Amount &balance() const override {
        return balance_;
      }

     private:
      const interface::Amount balance_{proto_->balance()};
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ACCOUNT_ASSET_HPP
