/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_BATCH_FACTORY_HPP
#define IROHA_TRANSACTION_BATCH_FACTORY_HPP

#include <memory>

#include "common/result.hpp"
#include "interfaces/common_objects/transaction_sequence_common.hpp"

namespace shared_model {
  namespace interface {

    class TransactionBatch;

    /**
     * Provides methods that create transaction batch from a single transaction,
     * or a collection of transactions. Field validator is used by default
     */
    class TransactionBatchFactory {
     public:
      virtual ~TransactionBatchFactory() = default;

      template <typename BatchType>
      using FactoryResult = iroha::expected::Result<BatchType, std::string>;

      /**
       * Create transaction batch out of collection of transactions
       * @param transactions collection of transactions, should be from the same
       * batch
       * @return valid batch of transactions or string error
       */
      virtual FactoryResult<std::unique_ptr<TransactionBatch>>
      createTransactionBatch(
          const types::SharedTxsCollectionType &transactions) const = 0;

      /**
       * Creates transaction batch from single transaction
       * @param transaction is transaction being validated and used to create
       * batch
       * @return batch with single transaction or string error
       * @note transactions in such batches may not have batch meta information
       */
      virtual FactoryResult<std::unique_ptr<TransactionBatch>>
      createTransactionBatch(
          std::shared_ptr<Transaction> transaction) const = 0;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_TRANSACTION_BATCH_FACTORY_HPP
