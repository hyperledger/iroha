/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_pending_transactions.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetPendingTransactions::GetPendingTransactions(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)) {}

    template GetPendingTransactions::GetPendingTransactions(
        GetPendingTransactions::TransportType &);
    template GetPendingTransactions::GetPendingTransactions(
        const GetPendingTransactions::TransportType &);
    template GetPendingTransactions::GetPendingTransactions(
        GetPendingTransactions::TransportType &&);

    GetPendingTransactions::GetPendingTransactions(
        const GetPendingTransactions &o)
        : GetPendingTransactions(o.proto_) {}

    GetPendingTransactions::GetPendingTransactions(
        GetPendingTransactions &&o) noexcept
        : GetPendingTransactions(std::move(o.proto_)) {}

  }  // namespace proto
}  // namespace shared_model
