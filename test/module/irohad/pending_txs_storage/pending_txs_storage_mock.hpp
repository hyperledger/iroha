/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PENDING_TXS_STORAGE_MOCK_HPP
#define IROHA_PENDING_TXS_STORAGE_MOCK_HPP

#include <gmock/gmock.h>
#include "pending_txs_storage/pending_txs_storage.hpp"

namespace iroha {

  class MockPendingTransactionStorage : public PendingTransactionStorage {
   public:
    MOCK_CONST_METHOD1(
        getPendingTransactions,
        shared_model::interface::types::SharedTxsCollectionType(
            const shared_model::interface::types::AccountIdType &account_id));
    MOCK_CONST_METHOD3(
        getPendingTransactions,
        expected::Result<Response, ErrorCode>(
            const shared_model::interface::types::AccountIdType &account_id,
            const shared_model::interface::types::TransactionsNumberType
                page_size,
            const std::optional<shared_model::interface::types::HashType>
                &first_tx_hash));
    MOCK_METHOD1(insertPresenceCache,
                 void(std::shared_ptr<ametsuchi::TxPresenceCache> &cache));
    MOCK_METHOD(void,
                removeTransaction,
                (shared_model::interface::types::HashType const &),
                (override));
    MOCK_METHOD(void,
                updatedBatchesHandler,
                (std::shared_ptr<MstState> const &),
                (override));
    MOCK_METHOD(
        void,
        removeBatch,
        (std::shared_ptr<shared_model::interface::TransactionBatch> const &),
        (override));
  };

}  // namespace iroha

#endif  // IROHA_PENDING_TXS_STORAGE_MOCK_HPP
