/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PENDING_TXS_STORAGE_HPP
#define IROHA_PENDING_TXS_STORAGE_HPP

#include <rxcpp/rx.hpp>
#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {

  /**
   * Interface of storage for not fully signed transactions.
   */
  class PendingTransactionStorage {
   public:
    /**
     * Get all the pending transactions associated with request originator
     * @param account_id - query creator
     * @return collection of interface::Transaction objects
     */
    virtual shared_model::interface::types::SharedTxsCollectionType
    getPendingTransactions(const shared_model::interface::types::AccountIdType
                               &account_id) const = 0;

    virtual ~PendingTransactionStorage() = default;
  };

}  // namespace iroha

#endif  // IROHA_PENDING_TXS_STORAGE_HPP
