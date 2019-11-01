/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_engine_response.hpp"

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetEngineResponse::GetEngineResponse(QueryType &&query)
        : TrivialProto(std::forward<QueryType>(query)),
          get_engine_response_{proto_->payload().get_engine_response()} {}

    template GetEngineResponse::GetEngineResponse(
        GetEngineResponse::TransportType &);
    template GetEngineResponse::GetEngineResponse(
        const GetEngineResponse::TransportType &);
    template GetEngineResponse::GetEngineResponse(
        GetEngineResponse::TransportType &&);

    GetEngineResponse::GetEngineResponse(const GetEngineResponse &o)
        : GetEngineResponse(o.proto_) {}

    GetEngineResponse::GetEngineResponse(GetEngineResponse &&o) noexcept
        : GetEngineResponse(std::move(o.proto_)) {}

    const std::string &GetEngineResponse::txHash() const {
      return get_engine_response_.tx_hash();
    }

  }  // namespace proto
}  // namespace shared_model
