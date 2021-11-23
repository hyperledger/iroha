/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_ordering_service_impl.hpp"

#include <boost/range/adaptor/indirected.hpp>
#include <boost/range/size.hpp>
#include <unordered_set>

#include "ametsuchi/tx_presence_cache.hpp"
#include "ametsuchi/tx_presence_cache_utils.hpp"
#include "common/visitor.hpp"
#include "datetime/time.hpp"
#include "interfaces/iroha_internal/proposal.hpp"
#include "interfaces/iroha_internal/transaction_batch.hpp"
#include "interfaces/iroha_internal/transaction_batch_helpers.hpp"
#include "interfaces/transaction.hpp"
#include "logger/logger.hpp"
#include "main/subscription.hpp"

using iroha::ordering::OnDemandOrderingServiceImpl;

OnDemandOrderingServiceImpl::OnDemandOrderingServiceImpl(
    size_t transaction_limit,
    std::shared_ptr<shared_model::interface::UnsafeProposalFactory>
        proposal_factory,
    std::shared_ptr<ametsuchi::TxPresenceCache> tx_cache,
    logger::LoggerPtr log,
    size_t number_of_proposals)
    : transaction_limit_(transaction_limit),
      number_of_proposals_(number_of_proposals),
      proposal_factory_(std::move(proposal_factory)),
      tx_cache_(std::move(tx_cache)),
      log_(std::move(log)) {}

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

bool OnDemandOrderingServiceImpl::isEmptyBatchesCache() const {
  return batches_cache_.isEmpty();
}

bool OnDemandOrderingServiceImpl::hasEnoughBatchesInCache() const {
  return batches_cache_.availableTxsCount() >= transaction_limit_;
}

void OnDemandOrderingServiceImpl::forCachedBatches(
    std::function<void(const BatchesSetType &)> const &f) const {
  batches_cache_.forCachedBatches(f);
}

// std::optional<std::shared_ptr<const shared_model::interface::Proposal>>
iroha::ordering::ProposalWithHash
OnDemandOrderingServiceImpl::onRequestProposal(
    consensus::Round const &req_round) {
  log_->debug("Requesting a proposal for {}", req_round);
  iroha::ordering::ProposalWithHash result_proposal;
  do {
    std::lock_guard<std::mutex> lock(proposals_mutex_);
    if (auto it = proposal_map_.find(req_round); it != proposal_map_.end()) {
      result_proposal = it->second;
      auto &[opt_proposal, hash] = result_proposal;
      if (opt_proposal) {
        assert((*opt_proposal)->transactions().size() > 0);
        assert(hash.size() && "empty hash for valid proposal");
      }
      break;
    }
    bool const is_current_round_or_next2 =
        (req_round.block_round == current_round_.block_round
             ? (req_round.reject_round - current_round_.reject_round)
             : (req_round.block_round - current_round_.block_round))
        <= 2ull;
    if (is_current_round_or_next2) {
      result_proposal = packNextProposals(req_round);
      auto &[opt_proposal, hash] = result_proposal;
      if (opt_proposal and (*opt_proposal)->transactions().size() > 0
          and hash.size() == 0) {
        log_->error("STRANGE-X");
      }
      //      if (opt_proposal) {
      //        assert((*opt_proposal)->transactions().size() > 0);
      //        assert(hash.size() && "empty hash for valid proposal");
      //      }
      getSubscription()->notify(EventTypes::kOnPackProposal, req_round);
    }
  } while (false);

  auto &[opt_proposal, hash] = result_proposal;
  if (opt_proposal and (*opt_proposal)->transactions().size() > 0
      and hash.size() == 0) {
    log_->error("STRANGE-Y");
  }
  log_->debug("onRequestProposal() {}, {}.",
              req_round,
              opt_proposal
                  ? fmt::format("returning a proposal with hash {} of {} txs",
                                hash,
                                boost::size((*opt_proposal)->transactions()))
                  : "NOT returning a proposal");
  return result_proposal;
}

iroha::ordering::ProposalWithHash
OnDemandOrderingServiceImpl::packNextProposals(const consensus::Round &round) {
  std::vector<std::shared_ptr<shared_model::interface::Transaction>> txs;
  if (!isEmptyBatchesCache())  // todo hasEnoughBatchesInCache?
    batches_cache_.getTransactions(transaction_limit_, txs);

  iroha::ordering::ProposalWithHash proposal_with_hash;
  if (txs.size()) {
    auto &[opt_proposal, hash] = proposal_with_hash;
    opt_proposal = proposal_factory_->unsafeCreateProposal(
        round.block_round,
        iroha::time::now(),
        txs | boost::adaptors::indirected);
    hash = shared_model::interface::Proposal::calculateHash(*opt_proposal);
    assert(boost::empty((*opt_proposal)->transactions()) || hash.size() > 0);
  }
  assert(proposal_map_.find(round) == proposal_map_.end());
  proposal_map_.emplace(round, proposal_with_hash);
  return proposal_with_hash;
}

void OnDemandOrderingServiceImpl::tryErase(
    const consensus::Round &current_round) {
  // find first round that is not less than current_round
  auto current_proposal_it = proposal_map_.lower_bound(current_round);
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

  detail::ProposalMapType new_proposal_map{current_proposal_it,
                                           proposal_map_.end()};

  {
    std::lock_guard<std::mutex> lock(proposals_mutex_);
    proposal_map_.swap(new_proposal_map);
  }

  auto &old_proposal_map = new_proposal_map;  // after swap it became old
  for (auto it = old_proposal_map.begin(); it != current_proposal_it; ++it) {
    log_->debug("tryErase: erased proposals for round {}", it->first);
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
  return proposal_map_.find(round) != proposal_map_.end();
}

shared_model::crypto::Hash OnDemandOrderingServiceImpl::getProposalHash(
    iroha::consensus::Round round) {
  return std::get<shared_model::crypto::Hash>(getProposalWithHash(round));
}

iroha::ordering::ProposalWithHash
OnDemandOrderingServiceImpl::getProposalWithHash(
    iroha::consensus::Round round) {
  std::lock_guard<std::mutex> lock(proposals_mutex_);
  auto it = proposal_map_.find(round);
  if (it != proposal_map_.end()) {
    auto &[opt_proposal, hash] = it->second;
    //    if (opt_proposal) {
    //      assert((*opt_proposal)->transactions().size());
    //      assert(hash.size() && "empty hash for valid proposal");
    //    }
    assert((*opt_proposal)->transactions().empty()
           || hash.size() && "empty hash for valid proposal");
    return it->second;
  }
  return {};
}

void OnDemandOrderingServiceImpl::processReceivedProposal(
    CollectionType batches) {
  batches_cache_.processReceivedProposal(std::move(batches));
}
