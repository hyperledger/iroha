/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ASSET_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ASSET_RESPONSE_HPP

#include "interfaces/query_responses/asset_response.hpp"

#include "backend/protobuf/common_objects/asset.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class AssetResponse final : public interface::AssetResponse {
     public:
      explicit AssetResponse(iroha::protocol::QueryResponse &query_response);

      const Asset &asset() const override;

     private:
      const iroha::protocol::AssetResponse &asset_response_;

      Asset asset_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ASSET_RESPONSE_HPP
