/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_pending_transactions.hpp"

namespace shared_model {
  namespace proto {

    GetPendingTransactions::GetPendingTransactions(
        iroha::protocol::Query &query)
        : pending_transactions_{query.payload().get_pending_transactions()},
          pagination_meta_{[&]() -> boost::optional<const TxPaginationMeta> {
            if (query.payload()
                    .get_pending_transactions()
                    .has_pagination_meta()) {
              return TxPaginationMeta{*query.mutable_payload()
                                           ->mutable_get_pending_transactions()
                                           ->mutable_pagination_meta()};
            }
            return boost::none;
          }()} {}

    boost::optional<const interface::TxPaginationMeta &>
    GetPendingTransactions::paginationMeta() const {
      if (pagination_meta_) {
        return pagination_meta_.value();
      }
      return boost::none;
    }

  }  // namespace proto
}  // namespace shared_model
