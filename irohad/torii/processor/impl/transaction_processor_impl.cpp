/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "torii/processor/transaction_processor_impl.hpp"

#include <boost/format.hpp>

#include "interfaces/iroha_internal/block.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_sequence.hpp"
#include "logger/logger.hpp"
#include "multi_sig_transactions/state/mst_state.hpp"
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
          return (boost::format(
                      "Stateful validation error: transaction %s "
                      "did not pass initial verification: "
                      "checking '%s', error code '%d', query arguments: %s")
                  % tx_hash % cmd_error.name % cmd_error.error_code
                  % cmd_error.error_extra)
              .str();
        }
        return (boost::format(
                    "Stateful validation error in transaction %s: "
                    "command '%s' with index '%d' did not pass "
                    "verification with code '%d', query arguments: %s")
                % tx_hash % cmd_error.name % cmd_error.index
                % cmd_error.error_code % cmd_error.error_extra)
            .str();
      }
    }  // namespace

    TransactionProcessorImpl::TransactionProcessorImpl(
        std::shared_ptr<PeerCommunicationService> pcs,
        std::shared_ptr<MstProcessor> mst_processor,
        std::shared_ptr<iroha::torii::StatusBus> status_bus,
        std::shared_ptr<shared_model::interface::TxStatusFactory>
            status_factory,
        logger::LoggerPtr log)
        : pcs_(std::move(pcs)),
          mst_processor_(std::move(mst_processor)),
          status_bus_(std::move(status_bus)),
          status_factory_(std::move(status_factory)),
          log_(std::move(log)),
          verified_proposal_subscription_(
              std::make_shared<VerifiedProposalSubscription>(
                  getSubscription()
                      ->getEngine<EventTypes,
                                  simulator::VerifiedProposalCreatorEvent>())),
          blocks_subscription_(std::make_shared<BlockSubscription>(
              getSubscription()
                  ->getEngine<EventTypes,
                              std::shared_ptr<
                                  const shared_model::interface::Block>>())),
          mst_state_update_subscription_(
              std::make_shared<MSTStateUpdateSubscription>(
                  getSubscription()
                      ->getEngine<EventTypes, std::shared_ptr<MstState>>())),
          mst_prepared_batches_subscription_(
              std::make_shared<MSTBatchesSubscription>(
                  getSubscription()->getEngine<EventTypes, DataType>())),
          mst_expired_batches_subscription_(
              std::make_shared<MSTBatchesSubscription>(
                  getSubscription()->getEngine<EventTypes, DataType>())) {
      // process stateful validation results
      verified_proposal_subscription_->setCallback(
          [this](auto,
                 auto &,
                 auto key,
                 simulator::VerifiedProposalCreatorEvent event) {
            if (not event.verified_proposal_result) {
              return;
            }

            const auto &proposal_and_errors = getVerifiedProposalUnsafe(event);

            // notify about failed txs
            const auto &errors = proposal_and_errors->rejected_transactions;
            for (const auto &tx_error : errors) {
              log_->info("{}", composeErrorMessage(tx_error));
              this->publishStatus(TxStatusType::kStatefulFailed,
                                  tx_error.tx_hash,
                                  tx_error.error);
            }
            // notify about success txs
            for (const auto &successful_tx :
                 proposal_and_errors->verified_proposal->transactions()) {
              log_->info("VerifiedProposalCreatorEvent StatefulValid: {}",
                         successful_tx.hash().hex());
              this->publishStatus(TxStatusType::kStatefulValid,
                                  successful_tx.hash());
            }
          });
      verified_proposal_subscription_
          ->subscribe<SubscriptionEngineHandlers::kYac>(
              0, EventTypes::kOnVerifiedProposal);

      blocks_subscription_->setCallback(
          [this](auto, auto &, auto const key, auto block) {
            for (const auto &tx : block->transactions()) {
              const auto &hash = tx.hash();
              log_->debug("Committed transaction: {}", hash.hex());
              this->publishStatus(TxStatusType::kCommitted, hash);
            }
            for (const auto &rejected_tx_hash :
                 block->rejected_transactions_hashes()) {
              log_->debug("Rejected transaction: {}", rejected_tx_hash.hex());
              this->publishStatus(TxStatusType::kRejected, rejected_tx_hash);
            }
          });
      blocks_subscription_->subscribe<SubscriptionEngineHandlers::kYac>(
          0, EventTypes::kOnBlock);
      // commit transactions
      mst_state_update_subscription_->setCallback(
          [this](auto, auto, auto const key, std::shared_ptr<MstState> state) {
            assert(EventTypes::kOnStateUpdate == key);
            log_->info("MST state updated");
            state->iterateTransactions([this](const auto &tx) {
              this->publishStatus(TxStatusType::kMstPending, tx->hash());
            });
          });
      mst_state_update_subscription_
          ->subscribe<SubscriptionEngineHandlers::kYac>(
              0, EventTypes::kOnStateUpdate);

      mst_prepared_batches_subscription_->setCallback(
          [this](auto, auto, auto const key, DataType batch) {
            assert(EventTypes::kOnPreparedBatches == key);
            log_->info("MST batch prepared");
            this->publishEnoughSignaturesStatus(batch->transactions());
            this->pcs_->propagate_batch(batch);
          });
      mst_prepared_batches_subscription_
          ->subscribe<SubscriptionEngineHandlers::kYac>(
              0, EventTypes::kOnPreparedBatches);

      mst_expired_batches_subscription_->setCallback(
          [this](auto, auto, auto const key, DataType batch) {
            assert(EventTypes::kOnExpiredBatches == key);
            log_->info("MST batch {} is expired", batch->reducedHash());
            for (auto &&tx : batch->transactions()) {
              this->publishStatus(TxStatusType::kMstExpired, tx->hash());
            }
          });
      mst_expired_batches_subscription_
          ->subscribe<SubscriptionEngineHandlers::kYac>(
              0, EventTypes::kOnExpiredBatches);
    }

    void TransactionProcessorImpl::batchHandle(
        std::shared_ptr<shared_model::interface::TransactionBatch>
            transaction_batch) const {
      log_->info("handle batch");
      if (transaction_batch->hasAllSignatures()
          and not mst_processor_->batchInStorage(transaction_batch)) {
        log_->info("propagating batch to PCS");
        this->publishEnoughSignaturesStatus(transaction_batch->transactions());
        pcs_->propagate_batch(transaction_batch);
      } else {
        log_->info("propagating batch to MST");
        mst_processor_->propagateBatch(transaction_batch);
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

    void TransactionProcessorImpl::publishEnoughSignaturesStatus(
        const shared_model::interface::types::SharedTxsCollectionType &txs)
        const {
      for (const auto &tx : txs) {
        this->publishStatus(TxStatusType::kEnoughSignaturesCollected,
                            tx->hash());
      }
    }
  }  // namespace torii
}  // namespace iroha
