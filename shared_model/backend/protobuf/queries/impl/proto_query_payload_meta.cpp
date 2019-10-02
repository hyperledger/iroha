/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_query_payload_meta.hpp"

namespace shared_model {
  namespace proto {

    QueryPayloadMeta::QueryPayloadMeta(iroha::protocol::QueryPayloadMeta &meta)
        : meta_{meta} {}

    const interface::types::AccountIdType &QueryPayloadMeta::creatorAccountId()
        const {
      return meta_.creator_account_id();
    }

    interface::types::CounterType QueryPayloadMeta::queryCounter() const {
      return meta_.query_counter();
    }

    interface::types::TimestampType QueryPayloadMeta::createdTime() const {
      return meta_.created_time();
    }

  }  // namespace proto
}  // namespace shared_model
