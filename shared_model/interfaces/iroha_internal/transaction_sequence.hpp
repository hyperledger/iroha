/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_SEQUENCE_HPP
#define IROHA_TRANSACTION_SEQUENCE_HPP

#include <optional>
#include "interfaces/common_objects/transaction_sequence_common.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Transaction sequence is the collection of transactions where:
     * 1. All transactions from the same batch are place contiguously
     * 2. All batches are full (no transaction from the batch can be outside
     * sequence)
     */
    class TransactionSequence {
     public:
      TransactionSequence() = delete;
      TransactionSequence(const TransactionSequence &) = default;
      TransactionSequence(TransactionSequence &&) = default;

      explicit TransactionSequence(const types::BatchesCollectionType &batches);

      /**
       * Retrieves transactions from all batches as single collection
       * @return all batches transactions
       */
      const types::SharedTxsCollectionType &transactions() const;

      /**
       * Get batches in transaction sequence
       * Note that transaction without batch meta are returned as batch with
       * single transaction
       * @return collection of batches from transaction sequence
       */
      const types::BatchesCollectionType &batches() const;

      std::string toString() const;

     private:
      types::BatchesCollectionType batches_;
      mutable std::optional<types::SharedTxsCollectionType> transactions_;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_SEQUENCE_HPP
