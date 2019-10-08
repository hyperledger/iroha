/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_account_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"

namespace shared_model {
  namespace proto {

    GetAccountTransactions::GetAccountTransactions(
        iroha::protocol::Query &query)
        : account_transactions_{query.payload().get_account_transactions()},
          pagination_meta_{*query.mutable_payload()
                                ->mutable_get_account_transactions()
                                ->mutable_pagination_meta()} {}

    const interface::types::AccountIdType &GetAccountTransactions::accountId()
        const {
      return account_transactions_.account_id();
    }

    const interface::TxPaginationMeta &GetAccountTransactions::paginationMeta()
        const {
      return pagination_meta_;
    }

  }  // namespace proto
}  // namespace shared_model
