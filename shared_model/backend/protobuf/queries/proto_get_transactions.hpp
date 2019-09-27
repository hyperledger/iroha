/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_TRANSACTIONS_HPP
#define IROHA_PROTO_GET_TRANSACTIONS_HPP

#include "interfaces/queries/get_transactions.hpp"

#include "cryptography/hash.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetTransactions final : public interface::GetTransactions {
     public:
      explicit GetTransactions(iroha::protocol::Query &query);

      const TransactionHashesType &transactionHashes() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetTransactions &get_transactions_;

      const TransactionHashesType transaction_hashes_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_TRANSACTIONS_HPP
