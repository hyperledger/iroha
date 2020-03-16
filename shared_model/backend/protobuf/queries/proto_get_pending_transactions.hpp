/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP
#define IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP

#include "interfaces/queries/get_pending_transactions.hpp"

#include <optional>
#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetPendingTransactions final
        : public interface::GetPendingTransactions {
     public:
      explicit GetPendingTransactions(iroha::protocol::Query &query);

      std::optional<std::reference_wrapper<const interface::TxPaginationMeta>>
      paginationMeta() const override;

     private:
      const iroha::protocol::GetPendingTransactions &pending_transactions_;
      std::optional<const TxPaginationMeta> pagination_meta_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_PENDING_TRANSACTIONS_HPP
