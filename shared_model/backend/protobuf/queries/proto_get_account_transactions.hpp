/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_GET_ACCOUNT_TRANSACTIONS_H
#define IROHA_GET_ACCOUNT_TRANSACTIONS_H

#include "interfaces/queries/get_account_transactions.hpp"

#include "backend/protobuf/queries/proto_tx_pagination_meta.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetAccountTransactions final
        : public interface::GetAccountTransactions {
     public:
      explicit GetAccountTransactions(iroha::protocol::Query &query);

      const interface::types::AccountIdType &accountId() const override;

      const interface::TxPaginationMeta &paginationMeta() const override;

     private:
      // ------------------------------| fields |-------------------------------

      const iroha::protocol::GetAccountTransactions &account_transactions_;
      const TxPaginationMeta pagination_meta_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_GET_ACCOUNT_TRANSACTIONS_H
