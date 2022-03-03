/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PENDING_TXS_STORAGE_HPP
#define IROHA_PENDING_TXS_STORAGE_HPP

#include <optional>

#include "ametsuchi/tx_presence_cache.hpp"
#include "common/result.hpp"
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/query_responses/pending_transactions_page_response.hpp"

namespace iroha {
  class MstState;

  /**
   * Interface of storage for not fully signed transactions.
   */
  class PendingTransactionStorage {
   public:
    /**
     * Possible error codes the storage may return instead of pending
     * transactions list
     */
    enum ErrorCode {
      kNotFound,  // there is no batch which first tx has specified hash
    };

    /**
     * Storage response message with sufficient interface for performing
     * pagination over the storage contents
     */
    struct Response {
      shared_model::interface::types::SharedTxsCollectionType transactions;
      shared_model::interface::types::TransactionsNumberType
          all_transactions_size;
      std::optional<
          shared_model::interface::PendingTransactionsPageResponse::BatchInfo>
          next_batch_info;

      Response() : all_transactions_size(0) {}
    };

    // TODO igor-egorov 2019-06-06 IR-516 remove deprecated interface
    /**
     * DEPRECATED (Replaced by the following method with an extended interface)
     * Going to be removed with the upcoming major release.
     *
     * Get all the pending transactions associated with request originator
     * @param account_id - query creator
     * @return collection of interface::Transaction objects
     */
    /*[[deprecated]]*/ virtual shared_model::interface::types::
        SharedTxsCollectionType
        getPendingTransactions(
            const shared_model::interface::types::AccountIdType &account_id)
            const = 0;

    /**
     * Stores TxPresenceCache ref, for checks.
     * @param cache - ref to the stored object.
     */
    virtual void insertPresenceCache(
        std::shared_ptr<ametsuchi::TxPresenceCache> &cache) = 0;

    /**
     * Fetch pending transactions associated with request originator
     * @param account_id - query creator
     * @param page_size - requested page size
     * @param first_tx_hash - an optional hash of the first transaction in the
     * batch that will be the starting point of returned transactions sequence
     * @param first_tx_time - an optional timestamp of first transaction that
     * will be included
     * @param last_tx_time - an optional timestamp of last transaction that
     * will be included
     * @return - Response message when query succeeded (next_batch_info might
     * not be set when the end is reached). One of ErrorCode in case of error.
     */
    virtual expected::Result<Response, ErrorCode> getPendingTransactions(
        const shared_model::interface::types::AccountIdType &account_id,
        const shared_model::interface::types::TransactionsNumberType page_size,
        const std::optional<shared_model::interface::types::HashType>
            &first_tx_hash,
        const std::optional<shared_model::interface::types::TimestampType>
            &first_tx_time,
        const std::optional<shared_model::interface::types::TimestampType>
            &last_tx_time) const = 0;

    virtual void removeTransaction(
        shared_model::interface::types::HashType const &hash) = 0;

    virtual void updatedBatchesHandler(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch) = 0;

    virtual void removeBatch(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch) = 0;

    virtual ~PendingTransactionStorage() = default;
  };

}  // namespace iroha

#endif  // IROHA_PENDING_TXS_STORAGE_HPP
