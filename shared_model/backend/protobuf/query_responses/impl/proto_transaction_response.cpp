/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_transaction_response.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    TransactionsResponse::TransactionsResponse(
        QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          transaction_response_{proto_->transactions_response()},
          transactions_{transaction_response_.transactions().begin(),
                        transaction_response_.transactions().end()} {}

    template TransactionsResponse::TransactionsResponse(
        TransactionsResponse::TransportType &);
    template TransactionsResponse::TransactionsResponse(
        const TransactionsResponse::TransportType &);
    template TransactionsResponse::TransactionsResponse(
        TransactionsResponse::TransportType &&);

    TransactionsResponse::TransactionsResponse(const TransactionsResponse &o)
        : TransactionsResponse(o.proto_) {}

    TransactionsResponse::TransactionsResponse(TransactionsResponse &&o)
        : TransactionsResponse(std::move(o.proto_)) {}

    interface::types::TransactionsCollectionType
    TransactionsResponse::transactions() const {
      return transactions_;
    }

  }  // namespace proto
}  // namespace shared_model
