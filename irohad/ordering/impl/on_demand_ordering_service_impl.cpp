/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_ordering_service_impl.hpp"

#include <string_view>
#include <unordered_set>

#include <boost/range/adaptor/indirected.hpp>
#include <boost/range/size.hpp>
#include "ametsuchi/tx_presence_cache.hpp"
#include "ametsuchi/tx_presence_cache_utils.hpp"
#include "common/visitor.hpp"
#include "datetime/time.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_batch_impl.hpp"
#include "interfaces/iroha_internal/transaction_batch_parser_impl.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"
#include "ordering/ordering_types.hpp"
#include "subscription/scheduler_impl.hpp"

using iroha::ordering::OnDemandOrderingServiceImpl;

namespace {
  auto parseProposal(
      shared_model::interface::types::TransactionsCollectionType const &txs) {
    shared_model::interface::types::SharedTxsCollectionType transactions;
    for (auto const &transaction : txs)
      transactions.push_back(clone(transaction));

    return shared_model::interface::TransactionBatchParserImpl().parseBatches(
        transactions);
  }

  void uploadBatches(
      iroha::ordering::BatchesCache::BatchesSetType &batches,
      shared_model::interface::types::TransactionsCollectionType const &txs) {
    auto batch_txs = parseProposal(txs);
    for (auto &txs : batch_txs) {
      batches.insert(
          std::make_shared<shared_model::interface::TransactionBatchImpl>(
              std::move(txs)));
    }
  }

  void uploadBatchesWithFilter(
      iroha::ordering::BloomFilter256 const &bf,
      iroha::ordering::BatchesCache::BatchesSetType &batches,
      shared_model::interface::types::TransactionsCollectionType const &txs) {
    auto batch_txs = parseProposal(txs);
    for (auto &txs : batch_txs) {
      auto batch =
          std::make_shared<shared_model::interface::TransactionBatchImpl>(
              std::move(txs));
      if (bf.test(batch->reducedHash()))
        batches.insert(batch);
    }
  }
}  // namespace

OnDemandOrderingServiceImpl::OnDemandOrderingServiceImpl(
    size_t transaction_limit,
    uint32_t max_proposal_pack,
    std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
        proposal_factory,
    std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
    logger::LoggerPtr log,
    size_t number_of_proposals)
    : transaction_limit_(transaction_limit),
      number_of_proposals_(number_of_proposals),
      max_proposal_pack_(max_proposal_pack),
      proposal_factory_(std::move(proposal_factory)),
      tx_cache_(std::move(tx_cache)),
      log_(std::move(log)) {
#if USE_BLOOM_FILTER
  remote_proposal_observer_ =
      SubscriberCreator<bool, RemoteProposalDownloadedEvent>::template create<
          iroha::EventTypes::kRemoteProposalDiff>(
          iroha::SubscriptionEngineHandlers::kProposalProcessing,
          [this](
              auto,
              auto ev) {  /// TODO(iceseer): remove `this` from lambda context
            BatchesCache::BatchesSetType batches;
            uploadBatches(batches, ev.remote->transactions());

            if (ev.bloom_filter.size() == BloomFilter256::kBytesCount) {
              BloomFilter256 bf;
              bf.store(ev.bloom_filter);
              uploadBatchesWithFilter(bf, batches, ev.local->transactions());
            }

            std::vector<std::shared_ptr<shared_model::interface::Transaction>>
                collection;
            for (auto const &batch : batches) {
              collection.insert(std::end(collection),
                                std::begin(batch->transactions()),
                                std::end(batch->transactions()));
            }
            if (auto result =
                    tryCreateProposal(ev.round, collection, ev.created_time);
                result
                && result.value()->hash()
                    == shared_model::crypto::Hash(ev.remote_proposal_hash)) {
              log_->debug("Local correct proposal: {}, while remote {}",
                          result.value()->hash(),
                          shared_model::crypto::Hash(ev.remote_proposal_hash));
              iroha::getSubscription()->notify(
                  iroha::EventTypes::kOnProposalResponse,
                  ProposalEvent{std::move(result).value(), ev.round});
            } else {
              if (result)
                log_->debug(
                    "Local incorrect proposal: {}\nwhile remote {}\nremote "
                    "proposal: {}\nlocal proposal: {}",
                    result.value()->hash(),
                    shared_model::crypto::Hash(ev.remote_proposal_hash),
                    *ev.remote,
                    **result);
              else
                log_->debug(
                    "Local proposal was not created while remote hash "
                    "{}\nremote proposal: {}",
                    shared_model::crypto::Hash(ev.remote_proposal_hash),
                    *ev.remote);
              iroha::getSubscription()->notify(
                  iroha::EventTypes::kOnProposalResponseFailed,
                  ProposalEvent{std::nullopt, ev.round});
            }
          });
#endif  // USE_BLOOM_FILTER
}

OnDemandOrderingServiceImpl::~OnDemandOrderingServiceImpl() {
#if USE_BLOOM_FILTER
  remote_proposal_observer_->unsubscribe();
#endif  // USE_BLOOM_FILTER
}

// -------------------------| OnDemandOrderingService |-------------------------

void OnDemandOrderingServiceImpl::onCollaborationOutcome(
    consensus::Round round) {
  log_->info("onCollaborationOutcome => {}", round);
  {
    std::lock_guard lock(proposals_mutex_);
    current_round_ = round;
  }
  tryErase(round);
}

void OnDemandOrderingServiceImpl::onBatches(CollectionType batches) {
  for (auto &batch : batches)
    if (not batchAlreadyProcessed(*batch))
      if (!insertBatchToCache(batch))
        break;

  log_->info("onBatches => collection size = {}", batches.size());
}

// ---------------------------------| Private |---------------------------------
bool OnDemandOrderingServiceImpl::insertBatchToCache(
    std::shared_ptr<shared_model::interface::TransactionBatch> const &batch) {
  auto const available_txs_count = batches_cache_.insert(batch);
  if (available_txs_count >= transaction_limit_)
    getSubscription()->notify(EventTypes::kOnTxsEnoughForProposal,
                              std::shared_ptr(batch));

  return true;
}

void OnDemandOrderingServiceImpl::removeFromBatchesCache(
    const OnDemandOrderingService::HashesSetType &hashes) {
  batches_cache_.remove(hashes);
}

bool OnDemandOrderingServiceImpl::isEmptyBatchesCache() {
  return batches_cache_.isEmpty();
}

uint32_t OnDemandOrderingServiceImpl::availableTxsCountBatchesCache() {
  return batches_cache_.availableTxsCount();
}

bool OnDemandOrderingServiceImpl::hasEnoughBatchesInCache() const {
  return batches_cache_.availableTxsCount() >= transaction_limit_;
}

void OnDemandOrderingServiceImpl::forCachedBatches(
    std::function<void(BatchesSetType &)> const &f) {
  batches_cache_.forCachedBatches(f);
}

iroha::ordering::PackedProposalData
OnDemandOrderingServiceImpl::waitForLocalProposal(
    consensus::Round const &round, std::chrono::milliseconds const &delay) {
  if (!hasProposal(round) && !hasEnoughBatchesInCache()) {
    auto scheduler = std::make_shared<subscription::SchedulerBase>();
    auto tid = getSubscription()->dispatcher()->bind(scheduler);

    auto batches_subscription = SubscriberCreator<
        bool,
        std::shared_ptr<shared_model::interface::TransactionBatch>>::
        template create<EventTypes::kOnTxsEnoughForProposal>(
            static_cast<iroha::SubscriptionEngineHandlers>(*tid),
            [scheduler(utils::make_weak(scheduler))](auto, auto) {
              if (auto maybe_scheduler = scheduler.lock())
                maybe_scheduler->dispose();
            });
    auto proposals_subscription =
        SubscriberCreator<bool, std::pair<consensus::Round, size_t>>::
            template create<EventTypes::kOnPackProposal>(
                static_cast<iroha::SubscriptionEngineHandlers>(*tid),
                [round, scheduler(utils::make_weak(scheduler))](
                    auto, auto packed_round_and_count) {
                  if (auto maybe_scheduler = scheduler.lock(); maybe_scheduler
                      and (round.block_round
                               >= packed_round_and_count.first.block_round
                           && round.block_round
                               < packed_round_and_count.first.block_round
                                   + packed_round_and_count.second))
                    maybe_scheduler->dispose();
                });
    scheduler->addDelayed(delay, [scheduler(utils::make_weak(scheduler))] {
      if (auto maybe_scheduler = scheduler.lock()) {
        maybe_scheduler->dispose();
      }
    });

    scheduler->process();
    getSubscription()->dispatcher()->unbind(*tid);
  }

  return onRequestProposal(round);
}

iroha::ordering::PackedProposalData
OnDemandOrderingServiceImpl::onRequestProposal(consensus::Round round) {
  log_->debug("Requesting a proposal for round {}", round);
  PackedProposalData result;
  do {
    std::lock_guard<std::mutex> lock(proposals_mutex_);
    auto it = proposal_map_.find(round.block_round);
    if (it != proposal_map_.end()) {
      result = it->second;
      break;
    }

    bool const is_current_round_or_next_pack =
        (round.block_round == current_round_.block_round
             ? (round.reject_round - current_round_.reject_round)
             : (round.block_round - current_round_.block_round))
        <= max_proposal_pack_ + 2ull;

    if (is_current_round_or_next_pack) {
      result = packNextProposals(round);
      if (result)
        proposal_map_.emplace(round.block_round, result);
      getSubscription()->notify(EventTypes::kOnPackProposal, round);
    }
  } while (false);

  log_->debug("uploadProposal, {}, {} returning a proposal.",
              round,
              result ? "" : "NOT ");
  return result;
}

std::optional<std::shared_ptr<shared_model::interface::Proposal>>
OnDemandOrderingServiceImpl::tryCreateProposal(
    consensus::Round const &round,
    const TransactionsCollectionType &txs,
    shared_model::interface::types::TimestampType created_time) {
  std::optional<std::shared_ptr<shared_model::interface::Proposal>> proposal;
  if (not txs.empty()) {
    proposal = proposal_factory_->unsafeCreateProposal(
        round.block_round, created_time, txs | boost::adaptors::indirected);
    log_->debug(
        "packNextProposal: data has been fetched for {}. "
        "Number of transactions in proposal = {}.",
        round,
        txs.size());
  } else {
    proposal = std::nullopt;
    log_->debug("No transactions to create a proposal for {}", round);
  }
  return proposal;
}

iroha::ordering::PackedProposalData
OnDemandOrderingServiceImpl::packNextProposals(const consensus::Round &round) {
  auto const available_txs_count = availableTxsCountBatchesCache();
  auto const full_proposals_count = available_txs_count / transaction_limit_;
  auto const number_of_proposals = std::min(
      (uint32_t)((available_txs_count
                  + (full_proposals_count > 0 ? 0 : transaction_limit_ - 1))
                 / transaction_limit_),
      max_proposal_pack_);

  PackedProposalContainer outcome;
  std::vector<std::shared_ptr<shared_model::interface::Transaction>> txs;
  BloomFilter256 bf;

  for (uint32_t ix = 0; ix < number_of_proposals; ++ix) {
    assert(!isEmptyBatchesCache());
    batches_cache_.getTransactions(
        transaction_limit_, txs, bf, [&](auto const &batch) {
          assert(batch);
          return batchAlreadyProcessed(*batch);
        });

    log_->debug(
        "Packed proposal {} contains: {} transactions.", ix, txs.size());
    if (auto result = tryCreateProposal(
            consensus::Round(round.block_round + ix,
                             ix == 0 ? round.reject_round : 0),
            txs,
            iroha::time::now()))
      outcome.emplace_back(std::make_pair(std::move(result).value(), bf));
    else
      break;
  }

  return outcome.empty() ? PackedProposalData{} : std::move(outcome);
}

void OnDemandOrderingServiceImpl::tryErase(
    const consensus::Round &current_round) {
  // find first round that is not less than current_round
  auto current_proposal_it =
      proposal_map_.lower_bound(current_round.block_round);
  // save at most number_of_proposals_ rounds that are less than current_round
  for (size_t i = 0; i < number_of_proposals_
       and current_proposal_it != proposal_map_.begin();
       ++i) {
    current_proposal_it--;
  }

  // do not proceed if there is nothing to remove
  if (current_proposal_it == proposal_map_.begin()) {
    return;
  }

  detail::ProposalMapType proposal_map{current_proposal_it,
                                       proposal_map_.end()};

  {
    std::lock_guard<std::mutex> lock(proposals_mutex_);
    proposal_map_.swap(proposal_map);
  }

  for (auto it = proposal_map.begin(); it != current_proposal_it; ++it) {
    log_->debug("tryErase: erased {}", it->first);
  }
}

bool OnDemandOrderingServiceImpl::batchAlreadyProcessed(
    const shared_model::interface::TransactionBatch &batch) {
  auto tx_statuses = tx_cache_->check(batch);
  if (not tx_statuses) {
    // TODO andrei 30.11.18 IR-51 Handle database error
    log_->warn("Check tx presence database error. Batch: {}", batch);
    return true;
  }
  // if any transaction is commited or rejected, batch was already processed
  // Note: any_of returns false for empty sequence
  return std::any_of(
      tx_statuses->begin(), tx_statuses->end(), [this](const auto &tx_status) {
        if (iroha::ametsuchi::isAlreadyProcessed(tx_status)) {
          log_->warn("Duplicate transaction: {}",
                     iroha::ametsuchi::getHash(tx_status).hex());
          return true;
        }
        return false;
      });
}

bool OnDemandOrderingServiceImpl::hasProposal(consensus::Round round) const {
  std::lock_guard<std::mutex> lock(proposals_mutex_);
  return proposal_map_.find(round.block_round) != proposal_map_.end();
}

void OnDemandOrderingServiceImpl::processReceivedProposal(
    CollectionType batches) {
  batches_cache_.processReceivedProposal(std::move(batches));
}
