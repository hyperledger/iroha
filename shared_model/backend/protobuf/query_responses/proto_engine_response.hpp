/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_ENGINE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_ENGINE_RESPONSE_HPP

#include "interfaces/query_responses/engine_response.hpp"

#include "interfaces/common_objects/range_types.hpp"
#include "backend/protobuf/query_responses/proto_engine_response_record.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class EngineResponse final : public interface::EngineResponse {
     public:
      explicit EngineResponse(iroha::protocol::QueryResponse &query_response);

      interface::types::EngineResponseRecordCollectionType
      engineResponseRecords() const override;

     private:
      const iroha::protocol::EngineResponse &engine_response_;

      const std::vector<proto::EngineResponseRecord> engine_response_records_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ENGINE_RESPONSE_HPP
