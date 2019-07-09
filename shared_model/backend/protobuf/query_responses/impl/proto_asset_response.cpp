/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_asset_response.hpp"

namespace shared_model {
  namespace proto {

    AssetResponse::AssetResponse(iroha::protocol::QueryResponse &query_response)
        : asset_response_{query_response.asset_response()},
          asset_{*query_response.mutable_asset_response()->mutable_asset()} {}

    const Asset &AssetResponse::asset() const {
      return asset_;
    }

  }  // namespace proto
}  // namespace shared_model
