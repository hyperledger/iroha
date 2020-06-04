/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_engine_receipts_response.hpp"

namespace shared_model {
  namespace proto {

    EngineReceiptsResponse::EngineReceiptsResponse(
        iroha::protocol::QueryResponse &query_response)
        : engine_response_{query_response.engine_receipts_response()},
          engine_response_records_{engine_response_.engine_receipts().begin(),
                                   engine_response_.engine_receipts().end()} {}

    interface::types::EngineReceiptCollectionType
    EngineReceiptsResponse::engineReceipts() const {
      return engine_response_records_;
    }

  }  // namespace proto
}  // namespace shared_model
