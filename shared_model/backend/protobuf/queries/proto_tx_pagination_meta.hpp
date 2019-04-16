/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP
#define IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/queries/tx_pagination_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {

    /// Provides query metadata for any transaction list pagination.
    class TxPaginationMeta final
        : public CopyableProto<interface::TxPaginationMeta,
                               iroha::protocol::TxPaginationMeta,
                               TxPaginationMeta> {
     public:
      explicit TxPaginationMeta(const TransportType &query);
      explicit TxPaginationMeta(TransportType &&query);
      TxPaginationMeta(const TxPaginationMeta &o);
      TxPaginationMeta(TxPaginationMeta &&o) noexcept;

      interface::types::TransactionsNumberType pageSize() const override;

      boost::optional<interface::types::HashType> firstTxHash() const override;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP
