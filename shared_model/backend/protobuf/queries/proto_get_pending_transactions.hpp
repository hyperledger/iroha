/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP
#define IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "interfaces/queries/get_pending_transactions.hpp"

#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetPendingTransactions final
        : public CopyableProto<interface::GetPendingTransactions,
                               iroha::protocol::Query,
                               GetPendingTransactions> {
     public:
      template <typename QueryType>
      explicit GetPendingTransactions(QueryType &&query);

      GetPendingTransactions(const GetPendingTransactions &o);

      GetPendingTransactions(GetPendingTransactions &&o) noexcept;

      boost::optional<const interface::TxPaginationMeta &> paginationMeta()
          const override;

     private:
      const iroha::protocol::GetPendingTransactions &pending_transactions_;
      boost::optional<const TxPaginationMeta> pagination_meta_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP
