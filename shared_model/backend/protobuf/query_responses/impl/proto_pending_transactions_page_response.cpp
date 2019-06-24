/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_pending_transactions_page_response.hpp"
#include "common/byteutils.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    PendingTransactionsPageResponse::PendingTransactionsPageResponse(
        QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          pending_transactions_page_response_{
              proto_->pending_transactions_page_response()},
          transactions_{proto_->mutable_pending_transactions_page_response()
                            ->mutable_transactions()
                            ->begin(),
                        proto_->mutable_pending_transactions_page_response()
                            ->mutable_transactions()
                            ->end()},
          next_batch_info_{
              [this]()
                  -> boost::optional<
                      interface::PendingTransactionsPageResponse::BatchInfo> {
                if (pending_transactions_page_response_.has_next_batch_info()) {
                  auto &next =
                      pending_transactions_page_response_.next_batch_info();
                  interface::PendingTransactionsPageResponse::BatchInfo
                      next_batch;
                  next_batch.first_tx_hash =
                      crypto::Hash::fromHexString(next.first_tx_hash());
                  next_batch.batch_size = next.batch_size();
                  return next_batch;
                }
                return boost::none;
              }()} {}

    template PendingTransactionsPageResponse::PendingTransactionsPageResponse(
        PendingTransactionsPageResponse::TransportType &);
    template PendingTransactionsPageResponse::PendingTransactionsPageResponse(
        const PendingTransactionsPageResponse::TransportType &);
    template PendingTransactionsPageResponse::PendingTransactionsPageResponse(
        PendingTransactionsPageResponse::TransportType &&);

    PendingTransactionsPageResponse::PendingTransactionsPageResponse(
        const PendingTransactionsPageResponse &o)
        : PendingTransactionsPageResponse(o.proto_) {}

    PendingTransactionsPageResponse::PendingTransactionsPageResponse(
        PendingTransactionsPageResponse &&o)
        : PendingTransactionsPageResponse(std::move(o.proto_)) {}

    interface::types::TransactionsCollectionType
    PendingTransactionsPageResponse::transactions() const {
      return transactions_;
    }

    boost::optional<interface::PendingTransactionsPageResponse::BatchInfo>
    PendingTransactionsPageResponse::nextBatchInfo() const {
      return next_batch_info_;
    }

    interface::types::TransactionsNumberType
    PendingTransactionsPageResponse::allTransactionsSize() const {
      return pending_transactions_page_response_.all_transactions_size();
    }

  }  // namespace proto
}  // namespace shared_model
