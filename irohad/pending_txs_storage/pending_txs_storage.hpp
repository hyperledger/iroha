/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PENDING_TXS_STORAGE_HPP
#define IROHA_PENDING_TXS_STORAGE_HPP

#include <boost/optional.hpp>
#include <rxcpp/rx.hpp>
#include "common/result.hpp"
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/common_objects/types.hpp"
#include "interfaces/query_responses/pending_transactions_page_response.hpp"

namespace iroha {

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
      NOT_FOUND,  // there is no batch which first tx has specified hash
    };

    /**
     * Storage response message with sufficient interface for performing
     * pagination over the storage contents
     */
    struct Response {
      shared_model::interface::types::SharedTxsCollectionType transactions;
      shared_model::interface::types::TransactionsNumberType
          all_transactions_size;
      boost::optional<
          shared_model::interface::PendingTransactionsPageResponse::BatchInfo>
          next_batch_info;

      Response() : all_transactions_size(0) {}
    };

    /**
     * DEPRECATED (Replaced by the following method with an extended interface)
     * Going to be removed with the upcoming major release.
     *
     * Get all the pending transactions associated with request originator
     * @param account_id - query creator
     * @return collection of interface::Transaction objects
     */
    [[deprecated]] virtual shared_model::interface::types::
        SharedTxsCollectionType
        getPendingTransactions(
            const shared_model::interface::types::AccountIdType &account_id)
            const = 0;

    /**
     * Fetch pending transactions associated with request originator
     * @param account_id - query creator
     * @param page_size - requested page size
     * @param first_tx_hash - an optional hash of the first transaction in the
     * batch that will be the starting point of returned transactions sequence
     * @return - Response message when query succeeded (next_batch_info might
     * not be set when the end is reached). One of ErrorCode in case of error.
     */
    virtual expected::Result<Response, ErrorCode> getPendingTransactions(
        const shared_model::interface::types::AccountIdType &account_id,
        const shared_model::interface::types::TransactionsNumberType &page_size,
        const boost::optional<shared_model::interface::types::HashType>
            first_tx_hash) const = 0;

    virtual ~PendingTransactionStorage() = default;
  };

}  // namespace iroha

#endif  // IROHA_PENDING_TXS_STORAGE_HPP
