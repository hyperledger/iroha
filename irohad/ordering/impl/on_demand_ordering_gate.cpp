/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_ordering_gate.hpp"

#include <iterator>

#include <boost/range/adaptor/filtered.hpp>
#include <boost/range/adaptor/indexed.hpp>
#include <boost/range/adaptor/transformed.hpp>
#include <boost/range/empty.hpp>
#include "ametsuchi/tx_presence_cache.hpp"
#include "ametsuchi/tx_presence_cache_utils.hpp"
#include "common/visitor.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "logger/logger.hpp"
#include "ordering/impl/on_demand_common.hpp"

using namespace iroha;
using namespace iroha::ordering;

OnDemandOrderingGate::OnDemandOrderingGate(
    std::shared_ptr<OnDemandOrderingService> ordering_service,
    std::unique_ptr<transport::OdOsNotification> network_client,
    std::shared_ptr<shared_model::interface::UnsafeProposalFactory> factory,
    std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
    std::shared_ptr<ProposalCreationStrategy> proposal_creation_strategy,
    size_t transaction_limit,
    logger::LoggerPtr log)
    : log_(std::move(log)),
      transaction_limit_(transaction_limit),
      ordering_service_(std::move(ordering_service)),
      network_client_(std::move(network_client)),
      proposal_factory_(std::move(factory)),
      tx_cache_(std::move(tx_cache)),
      processed_hashes_subscription_(
          std::make_shared<ProcessedHashesSubscriberType>(
              getSubscription()
                  ->getEngine<EventTypes,
                              std::shared_ptr<cache::OrderingGateCache::
                                                  HashesSetType>>())),
      round_switch_subscription_(std::make_shared<RoundSwitchSubscriberType>(
          getSubscription()->getEngine<EventTypes, RoundSwitch>()))
{
  processed_hashes_subscription_->setCallback(
      [this](auto, auto &, auto key, auto hashes) {
        assert(EventTypes::kOnProcessedHashes == key);
        // remove transaction hashes from cache
        log_->debug("Asking to remove {} transactions from cache.",
                    hashes->size());
        ordering_service_->onTxsCommitted(*hashes);
      });
  round_switch_subscription_->setCallback(
      [this,
       proposal_creation_strategy = std::move(proposal_creation_strategy)](
          auto, auto &, auto key, auto event) {
        assert(EventTypes::kOnRoundSwitch == key);
        log_->debug("Current: {}", event.next_round);
        log_->error("==========================");

        std::shared_lock<std::shared_timed_mutex> stop_lock(stop_mutex_);
        if (stop_requested_) {
          log_->warn("Not doing anything because stop was requested.");
          return;
        }

        // notify our ordering service about new round
        proposal_creation_strategy->onCollaborationOutcome(
            event.next_round, event.ledger_state->ledger_peers.size());
        ordering_service_->onCollaborationOutcome(event.next_round);

        this->sendCachedTransactions();

        // request proposal for the current round
        auto proposal = this->processProposalRequest(
            network_client_->onRequestProposal(event.next_round));
        // vote for the object received from the network
        getSubscription()->notify(
            EventTypes::kOnProposal,
            network::OrderingEvent{std::move(proposal),
                                   event.next_round,
                                   std::move(event.ledger_state)});
      });

  round_switch_subscription_->subscribe<SubscriptionEngineHandlers::kYac>(
      0, EventTypes::kOnRoundSwitch);
  processed_hashes_subscription_->subscribe<SubscriptionEngineHandlers::kYac>(
      0, EventTypes::kOnProcessedHashes);
}

OnDemandOrderingGate::~OnDemandOrderingGate() {
  stop();
}

void OnDemandOrderingGate::propagateBatch(
    std::shared_ptr<shared_model::interface::TransactionBatch> batch) {
  std::shared_lock<std::shared_timed_mutex> stop_lock(stop_mutex_);
  if (stop_requested_) {
    log_->warn("Not propagating {} because stop was requested.", *batch);
    return;
  }

  // TODO iceseer 14.01.21 IR-959 Refactor to avoid copying.
  ordering_service_->onBatches(
      transport::OdOsNotification::CollectionType{batch});
  network_client_->onBatches(
      transport::OdOsNotification::CollectionType{batch});
}

void OnDemandOrderingGate::stop() {
  std::lock_guard<std::shared_timed_mutex> stop_lock(stop_mutex_);
  if (not stop_requested_) {
    stop_requested_ = true;
    log_->info("Stopping.");
    processed_hashes_subscription_->unsubscribe();
    round_switch_subscription_->unsubscribe();
    network_client_.reset();
  }
}

boost::optional<std::shared_ptr<const shared_model::interface::Proposal>>
OnDemandOrderingGate::processProposalRequest(
    boost::optional<
        std::shared_ptr<const OnDemandOrderingService::ProposalType>> proposal)
    const {
  if (not proposal) {
    return boost::none;
  }
  auto proposal_without_replays =
      removeReplaysAndDuplicates(*std::move(proposal));
  // no need to check empty proposal
  if (boost::empty(proposal_without_replays->transactions())) {
    return boost::none;
  }
  return proposal_without_replays;
}

void OnDemandOrderingGate::sendCachedTransactions() {
  assert(not stop_mutex_.try_lock());  // lock must be taken before
  // TODO iceseer 14.01.21 IR-958 Check that OS is remote
  ordering_service_->forCachedBatches([this](auto const &batches) {
    auto end_iterator = batches.begin();
    auto current_number_of_transactions = 0u;
    for (; end_iterator != batches.end(); ++end_iterator) {
      auto batch_size = (*end_iterator)->transactions().size();
      if (current_number_of_transactions + batch_size <= transaction_limit_) {
        current_number_of_transactions += batch_size;
      } else {
        break;
      }
    }

    if (not batches.empty()) {
      network_client_->onBatches(transport::OdOsNotification::CollectionType{
          batches.begin(), end_iterator});
    }
  });
}

std::shared_ptr<const shared_model::interface::Proposal>
OnDemandOrderingGate::removeReplaysAndDuplicates(
    std::shared_ptr<const shared_model::interface::Proposal> proposal) const {
  std::vector<bool> proposal_txs_validation_results;
  auto tx_is_not_processed = [this](const auto &tx) {
    auto tx_result = tx_cache_->check(tx.hash());
    if (not tx_result) {
      // TODO andrei 30.11.18 IR-51 Handle database error
      return false;
    }
    // TODO nickaleks 21.11.18: IR-1887 log replayed transactions
    return !ametsuchi::isAlreadyProcessed(*tx_result);
  };

  std::unordered_set<std::string> hashes;
  auto tx_is_unique = [&hashes](const auto &tx) {
    auto tx_hash = tx.hash().hex();

    if (hashes.count(tx_hash)) {
      return false;
    } else {
      hashes.insert(tx_hash);
      return true;
    }
  };

  shared_model::interface::TransactionBatchParserImpl batch_parser;

  bool has_invalid_txs = false;
  auto batches = batch_parser.parseBatches(proposal->transactions());
  for (auto &batch : batches) {
    bool txs_are_valid =
        std::all_of(batch.begin(), batch.end(), [&](const auto &tx) {
          return tx_is_not_processed(tx) and tx_is_unique(tx);
        });
    proposal_txs_validation_results.insert(
        proposal_txs_validation_results.end(), batch.size(), txs_are_valid);
    has_invalid_txs |= not txs_are_valid;
  }

  if (not has_invalid_txs) {
    return proposal;
  }

  auto unprocessed_txs =
      proposal->transactions() | boost::adaptors::indexed()
      | boost::adaptors::filtered(
            [proposal_txs_validation_results =
                 std::move(proposal_txs_validation_results)](const auto &el) {
              return proposal_txs_validation_results.at(el.index());
            })
      | boost::adaptors::transformed(
            [](const auto &el) -> decltype(auto) { return el.value(); });

  return proposal_factory_->unsafeCreateProposal(
      proposal->height(), proposal->createdTime(), unprocessed_txs);
}
