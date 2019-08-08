/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_QUERY_PAYLOAD_META_HPP
#define IROHA_SHARED_MODEL_PROTO_QUERY_PAYLOAD_META_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/query_payload_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class QueryPayloadMeta final
        : public TrivialProto<interface::QueryPayloadMeta,
                              iroha::protocol::QueryPayloadMeta> {
     public:
      template <typename QueryPayloadMetaType>
      explicit QueryPayloadMeta(QueryPayloadMetaType &&query);

      QueryPayloadMeta(const QueryPayloadMeta &o);

      QueryPayloadMeta(QueryPayloadMeta &&o) noexcept;

      const interface::types::AccountIdType &creatorAccountId() const override;

      interface::types::CounterType queryCounter() const override;

      interface::types::TimestampType createdTime() const override;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_QUERY_HPP
