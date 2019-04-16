/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_asset_response.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    AssetResponse::AssetResponse(QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          asset_response_{proto_->asset_response()},
          asset_{asset_response_.asset()} {}

    template AssetResponse::AssetResponse(AssetResponse::TransportType &);
    template AssetResponse::AssetResponse(const AssetResponse::TransportType &);
    template AssetResponse::AssetResponse(AssetResponse::TransportType &&);

    AssetResponse::AssetResponse(const AssetResponse &o)
        : AssetResponse(o.proto_) {}

    AssetResponse::AssetResponse(AssetResponse &&o)
        : AssetResponse(std::move(o.proto_)) {}

    const Asset &AssetResponse::asset() const {
      return asset_;
    }

  }  // namespace proto
}  // namespace shared_model
