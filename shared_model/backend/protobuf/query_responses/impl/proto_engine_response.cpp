/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_engine_response.hpp"

namespace shared_model {
  namespace proto {

    EngineResponse::EngineResponse(
        iroha::protocol::QueryResponse &query_response)
        : engine_response_{query_response.engine_response()},
          engine_response_records_{
              engine_response_.engine_response_records().begin(),
              engine_response_.engine_response_records().end()} {}

    interface::types::EngineResponseRecordCollectionType
    EngineResponse::engineResponseRecords() const {
      return engine_response_records_;
    }

  }  // namespace proto
}  // namespace shared_model
