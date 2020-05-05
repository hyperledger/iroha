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
    class EngineReceiptsResponse final : public interface::EngineReceiptsResponse {
     public:
      explicit EngineReceiptsResponse(iroha::protocol::QueryResponse &query_response);

      interface::types::EngineReceiptCollectionType
      engineReceipts() const override;

     private:
      const iroha::protocol::EngineReceiptsResponse &engine_response_;

      const std::vector<proto::EngineReceipt> engine_response_records_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_ENGINE_RESPONSE_HPP
