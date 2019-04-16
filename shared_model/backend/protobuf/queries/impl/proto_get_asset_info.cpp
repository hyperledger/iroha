/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_asset_info.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetAssetInfo::GetAssetInfo(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)),
          asset_info_{proto_->payload().get_asset_info()} {}

    template GetAssetInfo::GetAssetInfo(GetAssetInfo::TransportType &);
    template GetAssetInfo::GetAssetInfo(const GetAssetInfo::TransportType &);
    template GetAssetInfo::GetAssetInfo(GetAssetInfo::TransportType &&);

    GetAssetInfo::GetAssetInfo(const GetAssetInfo &o)
        : GetAssetInfo(o.proto_) {}

    GetAssetInfo::GetAssetInfo(GetAssetInfo &&o) noexcept
        : GetAssetInfo(std::move(o.proto_)) {}

    const interface::types::AssetIdType &GetAssetInfo::assetId() const {
      return asset_info_.asset_id();
    }

  }  // namespace proto
}  // namespace shared_model
