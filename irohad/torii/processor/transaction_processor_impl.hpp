/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_TRANSACTION_PROCESSOR_STUB_HPP
#define IROHA_TRANSACTION_PROCESSOR_STUB_HPP

#include "torii/processor/transaction_processor.hpp"

#include "interfaces/common_objects/transaction_sequence_common.hpp"
#include "interfaces/iroha_internal/tx_status_factory.hpp"
#include "interfaces/transaction_responses/tx_response.hpp"
#include "logger/logger_fwd.hpp"
#include "network/peer_communication_service.hpp"
#include "torii/status_bus.hpp"
#include "validation/stateful_validator_common.hpp"

namespace iroha {
  namespace torii {
    class TransactionProcessorImpl : public TransactionProcessor {
     public:
      /**
       * @param pcs - provide information proposals and commits
       * @param mst_processor is a handler for multisignature transactions
       * @param status_bus is a common notifier for tx statuses
       * @param status_factory creates transaction statuses
       * @param log to print the progress
       */
      TransactionProcessorImpl(
          std::shared_ptr<network::PeerCommunicationService> pcs,
          std::shared_ptr<iroha::torii::StatusBus> status_bus,
          std::shared_ptr<shared_model::interface::TxStatusFactory>
              status_factory,
          logger::LoggerPtr log);

      void batchHandle(
          std::shared_ptr<shared_model::interface::TransactionBatch>
              transaction_batch) const override;

      void processVerifiedProposalCreatorEvent(
          simulator::VerifiedProposalCreatorEvent const &event) override;

      void processCommit(
          std::shared_ptr<const shared_model::interface::Block> const &block)
          override;

      void processStateUpdate(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) override;
      void processPreparedBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) override;
      void processExpiredBatch(
          std::shared_ptr<shared_model::interface::TransactionBatch> const
              &batch) override;

     private:
      // connections
      std::shared_ptr<network::PeerCommunicationService> pcs_;

      std::shared_ptr<iroha::torii::StatusBus> status_bus_;

      // keeps hashes of transaction, which were committed during this round
      std::vector<shared_model::interface::types::HashType> current_txs_hashes_;

      // creates transaction status
      std::shared_ptr<shared_model::interface::TxStatusFactory> status_factory_;

      logger::LoggerPtr log_;

      // TODO: [IR-1665] Akvinikym 29.08.18: Refactor method publishStatus(..)
      /**
       * Complementary class for publishStatus method
       */
      enum class TxStatusType {
        kStatelessFailed,
        kStatelessValid,
        kStatefulFailed,
        kStatefulValid,
        kRejected,
        kCommitted,
        kMstExpired,
        kNotReceived,
        kMstPending,
        kEnoughSignaturesCollected
      };
      /**
       * Publish status of transaction
       * @param tx_status to be published
       * @param hash of that transaction
       * @param cmd_error, which can appear during validation
       */
      void publishStatus(TxStatusType tx_status,
                         const shared_model::crypto::Hash &hash,
                         const validation::CommandError &cmd_error =
                             validation::CommandError{}) const;
    };
  }  // namespace torii
}  // namespace iroha

#endif  // IROHA_TRANSACTION_PROCESSOR_STUB_HPP
