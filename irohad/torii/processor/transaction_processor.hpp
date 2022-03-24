/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_PROCESSOR_HPP
#define IROHA_TRANSACTION_PROCESSOR_HPP

#include <memory>

#include "interfaces/common_objects/transaction_sequence_common.hpp"

namespace shared_model {
  namespace interface {
    class Block;
    class TransactionBatch;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  class MstState;
  namespace simulator {
    struct VerifiedProposalCreatorEvent;
  }
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

      virtual void processVerifiedProposalCreatorEvent(
          simulator::VerifiedProposalCreatorEvent const &event) = 0;

      virtual void processCommit(
          std::shared_ptr<shared_model::interface::Block const> const
              &block) = 0;

      virtual void processStateUpdate(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) = 0;

      virtual void processPreparedBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) = 0;

      virtual void processExpiredBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) = 0;

      virtual ~TransactionProcessor() = default;
    };
  }  // namespace torii
}  // namespace iroha
#endif  // IROHA_TRANSACTION_PROCESSOR_HPP
