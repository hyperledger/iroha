/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_transactions_page_response.hpp"
#include "common/byteutils.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    TransactionsPageResponse::TransactionsPageResponse(
        QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          transactionPageResponse_{proto_->transactions_page_response()},
          transactions_{transactionPageResponse_.transactions().begin(),
                        transactionPageResponse_.transactions().end()},
          next_hash_{[this]() -> boost::optional<interface::types::HashType> {
            switch (transactionPageResponse_.next_page_tag_case()) {
              case iroha::protocol::TransactionsPageResponse::kNextTxHash:
                return crypto::Hash::fromHexString(
                    transactionPageResponse_.next_tx_hash());
              default:
                return boost::none;
            }
          }()} {}

    template TransactionsPageResponse::TransactionsPageResponse(
        TransactionsPageResponse::TransportType &);
    template TransactionsPageResponse::TransactionsPageResponse(
        const TransactionsPageResponse::TransportType &);
    template TransactionsPageResponse::TransactionsPageResponse(
        TransactionsPageResponse::TransportType &&);

    TransactionsPageResponse::TransactionsPageResponse(
        const TransactionsPageResponse &o)
        : TransactionsPageResponse(o.proto_) {}

    TransactionsPageResponse::TransactionsPageResponse(
        TransactionsPageResponse &&o)
        : TransactionsPageResponse(std::move(o.proto_)) {}

    interface::types::TransactionsCollectionType
    TransactionsPageResponse::transactions() const {
      return transactions_;
    }

    boost::optional<interface::types::HashType>
    TransactionsPageResponse::nextTxHash() const {
      return next_hash_;
    }

    interface::types::TransactionsNumberType
    TransactionsPageResponse::allTransactionsSize() const {
      return transactionPageResponse_.all_transactions_size();
    }

  }  // namespace proto
}  // namespace shared_model
