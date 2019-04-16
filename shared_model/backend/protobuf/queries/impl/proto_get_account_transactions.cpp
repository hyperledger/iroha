/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_account_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetAccountTransactions::GetAccountTransactions(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)),
          account_transactions_{proto_->payload().get_account_transactions()},
          pagination_meta_{account_transactions_.pagination_meta()} {}

    template GetAccountTransactions::GetAccountTransactions(
        GetAccountTransactions::TransportType &);
    template GetAccountTransactions::GetAccountTransactions(
        const GetAccountTransactions::TransportType &);
    template GetAccountTransactions::GetAccountTransactions(
        GetAccountTransactions::TransportType &&);

    GetAccountTransactions::GetAccountTransactions(
        const GetAccountTransactions &o)
        : GetAccountTransactions(o.proto_) {}

    GetAccountTransactions::GetAccountTransactions(
        GetAccountTransactions &&o) noexcept
        : GetAccountTransactions(std::move(o.proto_)) {}

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
