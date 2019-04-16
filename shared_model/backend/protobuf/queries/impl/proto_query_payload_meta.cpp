/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_query_payload_meta.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryPayloadMetaType>
    QueryPayloadMeta::QueryPayloadMeta(QueryPayloadMetaType &&query)
        : CopyableProto(std::forward<QueryPayloadMetaType>(query)) {}

    template QueryPayloadMeta::QueryPayloadMeta(
        QueryPayloadMeta::TransportType &);
    template QueryPayloadMeta::QueryPayloadMeta(
        const QueryPayloadMeta::TransportType &);
    template QueryPayloadMeta::QueryPayloadMeta(
        QueryPayloadMeta::TransportType &&);

    QueryPayloadMeta::QueryPayloadMeta(const QueryPayloadMeta &o)
        : QueryPayloadMeta(o.proto_) {}

    QueryPayloadMeta::QueryPayloadMeta(QueryPayloadMeta &&o) noexcept
        : QueryPayloadMeta(std::move(o.proto_)) {}

    const interface::types::AccountIdType &QueryPayloadMeta::creatorAccountId()
        const {
      return proto_->creator_account_id();
    }

    interface::types::CounterType QueryPayloadMeta::queryCounter() const {
      return proto_->query_counter();
    }

    interface::types::TimestampType QueryPayloadMeta::createdTime() const {
      return proto_->created_time();
    }

  }  // namespace proto
}  // namespace shared_model
