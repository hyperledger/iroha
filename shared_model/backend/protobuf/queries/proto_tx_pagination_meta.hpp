/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP
#define IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP

#include "interfaces/queries/tx_pagination_meta.hpp"

#include "interfaces/common_objects/types.hpp"
#include "queries.pb.h"

#include "proto_ordering.hpp"

namespace shared_model {
  namespace proto {

    /// Provides query metadata for any transaction list pagination.
    class TxPaginationMeta final : public interface::TxPaginationMeta {
     public:
      explicit TxPaginationMeta(iroha::protocol::TxPaginationMeta &meta);

      interface::types::TransactionsNumberType pageSize() const override;

      std::optional<interface::types::HashType> firstTxHash() const override;
      interface::Ordering const &ordering() const override;

     private:
      const iroha::protocol::TxPaginationMeta &meta_;
      OrderingImpl ordering_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_PROTO_MODEL_QUERY_TX_PAGINATION_META_HPP
