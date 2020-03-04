/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP

#include "interfaces/query_responses/pending_transactions_page_response.hpp"

#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/types.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class PendingTransactionsPageResponse final
        : public interface::PendingTransactionsPageResponse {
     public:
      explicit PendingTransactionsPageResponse(
          iroha::protocol::QueryResponse &query_response);

      interface::types::TransactionsCollectionType transactions()
          const override;

      std::optional<interface::PendingTransactionsPageResponse::BatchInfo>
      nextBatchInfo() const override;

      interface::types::TransactionsNumberType allTransactionsSize()
          const override;

     private:
      const iroha::protocol::PendingTransactionsPageResponse
          &pending_transactions_page_response_;
      const std::vector<Transaction> transactions_;
      std::optional<interface::PendingTransactionsPageResponse::BatchInfo>
          next_batch_info_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP
