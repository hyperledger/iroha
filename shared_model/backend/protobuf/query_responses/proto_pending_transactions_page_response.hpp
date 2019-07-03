/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP

#include "interfaces/query_responses/pending_transactions_page_response.hpp"

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/types.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class PendingTransactionsPageResponse final
        : public CopyableProto<interface::PendingTransactionsPageResponse,
                               iroha::protocol::QueryResponse,
                               PendingTransactionsPageResponse> {
     public:
      template <typename QueryResponseType>
      explicit PendingTransactionsPageResponse(
          QueryResponseType &&queryResponse);

      PendingTransactionsPageResponse(const PendingTransactionsPageResponse &o);

      PendingTransactionsPageResponse(PendingTransactionsPageResponse &&o);

      interface::types::TransactionsCollectionType transactions()
          const override;

      boost::optional<interface::PendingTransactionsPageResponse::BatchInfo>
      nextBatchInfo() const override;

      interface::types::TransactionsNumberType allTransactionsSize()
          const override;

     private:
      const iroha::protocol::PendingTransactionsPageResponse
          &pending_transactions_page_response_;
      const std::vector<proto::Transaction> transactions_;
      boost::optional<interface::PendingTransactionsPageResponse::BatchInfo>
          next_batch_info_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_PENDING_TRANSACTIONS_PAGE_RESPONSE_HPP
