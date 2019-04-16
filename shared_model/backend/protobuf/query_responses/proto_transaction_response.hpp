/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_TRANSACTION_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_TRANSACTION_RESPONSE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "backend/protobuf/transaction.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/query_responses/transactions_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class TransactionsResponse final
        : public CopyableProto<interface::TransactionsResponse,
                               iroha::protocol::QueryResponse,
                               TransactionsResponse> {
     public:
      template <typename QueryResponseType>
      explicit TransactionsResponse(QueryResponseType &&queryResponse);

      TransactionsResponse(const TransactionsResponse &o);

      TransactionsResponse(TransactionsResponse &&o);

      interface::types::TransactionsCollectionType transactions()
          const override;

     private:
      const iroha::protocol::TransactionsResponse &transaction_response_;

      const std::vector<proto::Transaction> transactions_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_TRANSACTION_RESPONSE_HPP
