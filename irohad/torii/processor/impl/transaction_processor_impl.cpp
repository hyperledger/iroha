/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/processor/transaction_processor_impl.hpp"

#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_sequence.hpp"
#include "logger/logger.hpp"
#include "simulator/verified_proposal_creator_common.hpp"
#include "validation/stateful_validator_common.hpp"

namespace iroha {
  namespace torii {

    using network::PeerCommunicationService;

    namespace {
      std::string composeErrorMessage(
          const validation::TransactionError &tx_hash_and_error) {
        const auto tx_hash = tx_hash_and_error.tx_hash.hex();
        const auto &cmd_error = tx_hash_and_error.error;
        if (not cmd_error.tx_passed_initial_validation) {
          return fmt::format(
              "Stateful validation error: transaction {} did not pass initial "
              "verification: checking '{}', error code '{}', query arguments: "
              "{}",
              tx_hash,
              cmd_error.name,
              cmd_error.error_code,
              cmd_error.error_extra);
        }
        return fmt::format(
            "Stateful validation error in transaction {}: "
            "command '{}' with index '{}' did not pass "
            "verification with code '{}', query arguments: {}",
            tx_hash,
            cmd_error.name,
            cmd_error.index,
            cmd_error.error_code,
            cmd_error.error_extra);
      }
    }  // namespace

    TransactionProcessorImpl::TransactionProcessorImpl(
        std::shared_ptr<PeerCommunicationService> pcs,
        std::shared_ptr<iroha::torii::StatusBus> status_bus,
        std::shared_ptr<shared_model::interface::TxStatusFactory>
            status_factory,
        logger::LoggerPtr log)
        : pcs_(std::move(pcs)),
          status_bus_(std::move(status_bus)),
          status_factory_(std::move(status_factory)),
          log_(std::move(log)) {}

    void TransactionProcessorImpl::batchHandle(
        std::shared_ptr<shared_model::interface::TransactionBatch>
            transaction_batch) const {
      log_->info("handle batch");
      pcs_->propagate_batch(transaction_batch);
    }

    void TransactionProcessorImpl::processVerifiedProposalCreatorEvent(
        simulator::VerifiedProposalCreatorEvent const &event) {
      if (not event.verified_proposal_result) {
        return;
      }

      const auto &proposal_and_errors = getVerifiedProposalUnsafe(event);

      // notify about failed txs
      const auto &errors = proposal_and_errors->rejected_transactions;
      for (const auto &tx_error : errors) {
        log_->info("{}", composeErrorMessage(tx_error));
        publishStatus(
            TxStatusType::kStatefulFailed, tx_error.tx_hash, tx_error.error);
      }
      // notify about success txs
      for (const auto &successful_tx :
           proposal_and_errors->verified_proposal->transactions()) {
        log_->info("VerifiedProposalCreatorEvent StatefulValid: {}",
                   successful_tx.hash().hex());
        publishStatus(TxStatusType::kStatefulValid, successful_tx.hash());
      }
    }

    void TransactionProcessorImpl::processCommit(
        std::shared_ptr<const shared_model::interface::Block> const &block) {
      for (const auto &tx : block->transactions()) {
        const auto &hash = tx.hash();
        log_->debug("Committed transaction: {}", hash.hex());
        publishStatus(TxStatusType::kCommitted, hash);
      }
      for (const auto &rejected_tx_hash :
           block->rejected_transactions_hashes()) {
        log_->debug("Rejected transaction: {}", rejected_tx_hash.hex());
        publishStatus(TxStatusType::kRejected, rejected_tx_hash);
      }
    }

    void TransactionProcessorImpl::processStateUpdate(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch) {
      log_->info("MST state updated");
      std::for_each(batch->transactions().begin(),
                    batch->transactions().end(),
                    [this](const auto &tx) {
                      publishStatus(TxStatusType::kMstPending, tx->hash());
                    });
    }

    void TransactionProcessorImpl::processPreparedBatch(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch) {
      log_->info("MST batch prepared");
      for (const auto &tx : batch->transactions())
        publishStatus(TxStatusType::kEnoughSignaturesCollected, tx->hash());
    }

    void TransactionProcessorImpl::processExpiredBatch(
        std::shared_ptr<shared_model::interface::TransactionBatch> const
            &batch) {
      log_->info("MST batch {} is expired", batch->reducedHash());
      for (auto &&tx : batch->transactions()) {
        publishStatus(TxStatusType::kMstExpired, tx->hash());
      }
    }

    void TransactionProcessorImpl::publishStatus(
        TxStatusType tx_status,
        const shared_model::crypto::Hash &hash,
        const validation::CommandError &cmd_error) const {
      auto tx_error = cmd_error.name.empty()
          ? shared_model::interface::TxStatusFactory::TransactionError{}
          : shared_model::interface::TxStatusFactory::TransactionError{
                cmd_error.name, cmd_error.index, cmd_error.error_code};
      switch (tx_status) {
        case TxStatusType::kStatelessFailed: {
          status_bus_->publish(
              status_factory_->makeStatelessFail(hash, tx_error));
          return;
        };
        case TxStatusType::kStatelessValid: {
          status_bus_->publish(
              status_factory_->makeStatelessValid(hash, tx_error));
          return;
        };
        case TxStatusType::kStatefulFailed: {
          status_bus_->publish(
              status_factory_->makeStatefulFail(hash, tx_error));
          return;
        };
        case TxStatusType::kStatefulValid: {
          status_bus_->publish(
              status_factory_->makeStatefulValid(hash, tx_error));
          return;
        };
        case TxStatusType::kRejected: {
          status_bus_->publish(status_factory_->makeRejected(hash, tx_error));
          return;
        };
        case TxStatusType::kCommitted: {
          status_bus_->publish(status_factory_->makeCommitted(hash, tx_error));
          return;
        };
        case TxStatusType::kMstExpired: {
          status_bus_->publish(status_factory_->makeMstExpired(hash, tx_error));
          return;
        };
        case TxStatusType::kNotReceived: {
          status_bus_->publish(
              status_factory_->makeNotReceived(hash, tx_error));
          return;
        };
        case TxStatusType::kMstPending: {
          status_bus_->publish(status_factory_->makeMstPending(hash, tx_error));
          return;
        };
        case TxStatusType::kEnoughSignaturesCollected: {
          status_bus_->publish(
              status_factory_->makeEnoughSignaturesCollected(hash, tx_error));
          return;
        };
      }
    }
  }  // namespace torii
}  // namespace iroha
