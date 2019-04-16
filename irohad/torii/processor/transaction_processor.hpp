/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_PROCESSOR_HPP
#define IROHA_TRANSACTION_PROCESSOR_HPP

#include <memory>

namespace shared_model {
  namespace interface {
    class TransactionBatch;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace torii {
    /**
     * Transaction processor is interface with start point
     * for processing transaction in the system
     */
    class TransactionProcessor {
     public:
      /**
       * Process batch and propagate it to the MST or PCS
       * @param transaction_batch - transaction batch for processing
       */
      virtual void batchHandle(
          std::shared_ptr<shared_model::interface::TransactionBatch>
              transaction_batch) const = 0;

      virtual ~TransactionProcessor() = default;
    };
  }  // namespace torii
}  // namespace iroha
#endif  // IROHA_TRANSACTION_PROCESSOR_HPP
