/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ENGINE_RESPONSE_H
#define IROHA_PROTO_GET_ENGINE_RESPONSE_H

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/get_engine_response.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetEngineResponse final
        : public TrivialProto<interface::GetEngineResponse,
                              iroha::protocol::Query> {
     public:
      template <typename QueryType>
      explicit GetEngineResponse(QueryType &&query);

      GetEngineResponse(const GetEngineResponse &o);

      GetEngineResponse(GetEngineResponse &&o) noexcept;

      const std::string &txHash() const override;

     private:
      // ------------------------------| fields |-------------------------------
      const iroha::protocol::GetEngineResponse &get_engine_response_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ENGINE_RESPONSE_H
