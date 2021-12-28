/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/yac_gate_impl.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "common/visitor.hpp"
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/outcome_messages.hpp"
#include "consensus/yac/storage/yac_common.hpp"
#include "consensus/yac/yac_hash_provider.hpp"
#include "consensus/yac/yac_peer_orderer.hpp"
#include "interfaces/common_objects/signature.hpp"
#include "interfaces/iroha_internal/block.hpp"
#include "logger/logger.hpp"
#include "simulator/block_creator.hpp"

namespace {
  auto getPublicKeys(
      const std::vector<iroha::consensus::yac::VoteMessage> &votes) {
    return boost::copy_range<
        shared_model::interface::types::PublicKeyCollectionType>(
        votes | boost::adaptors::transformed([](auto &vote) {
          return vote.signature->publicKey();
        }));
  }
}  // namespace

using iroha::consensus::yac::YacGateImpl;

YacGateImpl::YacGateImpl(
    std::shared_ptr<HashGate> hash_gate,
    std::shared_ptr<YacPeerOrderer> orderer,
    std::optional<ClusterOrdering> alternative_order,
    std::shared_ptr<const LedgerState> ledger_state,
    std::shared_ptr<YacHashProvider> hash_provider,
    std::shared_ptr<consensus::ConsensusResultCache> consensus_result_cache,
    logger::LoggerPtr log)
    : log_(std::move(log)),
      current_hash_(),
      alternative_order_(std::move(alternative_order)),
      current_ledger_state_(std::move(ledger_state)),
      orderer_(std::move(orderer)),
      hash_provider_(std::move(hash_provider)),
      consensus_result_cache_(std::move(consensus_result_cache)),
      hash_gate_(std::move(hash_gate)) {}

void YacGateImpl::vote(const simulator::BlockCreatorEvent &event) {
  if (current_hash_.vote_round != event.round) {
    log_->info("Current round {} not equal to vote round {}, skipped",
               current_hash_.vote_round,
               event.round);
    return;
  }

  current_ledger_state_ = event.ledger_state;
  current_hash_ = hash_provider_->makeHash(event);
  assert(current_hash_.vote_round.block_round
         == current_ledger_state_->top_block_info.height + 1);

  if (not event.round_data) {
    current_block_ = std::nullopt;
    // previous block is committed to block storage, it is safe to clear
    // the cache
    // TODO 2019-03-15 andrei: IR-405 Subscribe BlockLoaderService to
    // BlockCreator::onBlock
    consensus_result_cache_->release();
    log_->debug("Agreed on nothing to commit");
  } else {
    current_block_ = event.round_data->block;
    // insert the block we voted for to the consensus cache
    consensus_result_cache_->insert(event.round_data->block);
    log_->info("vote for (proposal: {}, block: {})",
               current_hash_.vote_hashes.proposal_hash,
               current_hash_.vote_hashes.block_hash);
  }

  auto order =
      orderer_->getOrdering(current_hash_, event.ledger_state->ledger_peers);
  if (not order) {
    log_->error("ordering doesn't provide peers => pass round");
    return;
  }

  hash_gate_->vote(current_hash_, *order, std::move(alternative_order_));
  alternative_order_.reset();
}

std::optional<iroha::consensus::GateObject> YacGateImpl::processOutcome(
    Answer const &outcome) {
  return visit_in_place(
      outcome,
      [this](const CommitMessage &msg) { return this->handleCommit(msg); },
      [this](const RejectMessage &msg) { return this->handleReject(msg); },
      [this](const FutureMessage &msg) { return this->handleFuture(msg); });
}

void YacGateImpl::stop() {
  hash_gate_->stop();
}

std::optional<iroha::consensus::GateObject> YacGateImpl::processRoundSwitch(
    consensus::Round const &round,
    std::shared_ptr<LedgerState const> ledger_state) {
  current_hash_ = YacHash();
  current_hash_.vote_round = round;
  current_ledger_state_ = std::move(ledger_state);
  current_block_ = std::nullopt;
  consensus_result_cache_->release();
  if (auto answer = hash_gate_->processRoundSwitch(
          current_hash_.vote_round,
          current_ledger_state_->ledger_peers,
          current_ledger_state_->ledger_syncing_peers)) {
    return processOutcome(*answer);
  }
  return std::nullopt;
}

void YacGateImpl::copySignatures(const CommitMessage &commit) {
  for (const auto &vote : commit.votes) {
    auto sig = vote.hash.block_signature;
    current_block_.value()->addSignature(
        shared_model::interface::types::SignedHexStringView{sig->signedData()},
        shared_model::interface::types::PublicKeyHexStringView{
            sig->publicKey()});
  }
}

std::optional<iroha::consensus::GateObject> YacGateImpl::handleCommit(
    const CommitMessage &msg) {
  const auto hash = getHash(msg.votes).value();
  if (hash.vote_round < current_hash_.vote_round) {
    log_->info("Current round {} is greater than commit round {}, skipped",
               current_hash_.vote_round,
               hash.vote_round);
    return std::nullopt;
  }

  assert(hash.vote_round.block_round == current_hash_.vote_round.block_round);
  assert(hash.vote_round.block_round
         == current_ledger_state_->top_block_info.height + 1);

  if (hash == current_hash_ and current_block_) {
    // if node has voted for the committed block
    // append signatures of other nodes
    this->copySignatures(msg);
    auto &block = current_block_.value();
    log_->info("consensus: commit top block: height {}, hash {}",
               block->height(),
               block->hash().hex());
    return PairValid(current_hash_.vote_round, current_ledger_state_, block);
  }

  auto public_keys = getPublicKeys(msg.votes);

  if (hash.vote_hashes.proposal_hash.empty()) {
    // if consensus agreed on nothing for commit
    log_->info("Consensus skipped round, voted for nothing");
    current_block_ = std::nullopt;
    return AgreementOnNone(
        hash.vote_round, current_ledger_state_, std::move(public_keys));
  }

  log_->info("Voted for another block, waiting for sync");
  current_block_ = std::nullopt;
  auto model_hash = hash_provider_->toModelHash(hash);
  return VoteOther(hash.vote_round,
                   current_ledger_state_,
                   std::move(public_keys),
                   std::move(model_hash));
}

std::optional<iroha::consensus::GateObject> YacGateImpl::handleReject(
    const RejectMessage &msg) {
  const auto hash = getHash(msg.votes).value();
  auto public_keys = getPublicKeys(msg.votes);
  if (hash.vote_round < current_hash_.vote_round) {
    log_->info("Current round {} is greater than reject round {}, skipped",
               current_hash_.vote_round,
               hash.vote_round);
    return std::nullopt;
  }

  assert(hash.vote_round.block_round == current_hash_.vote_round.block_round);
  assert(hash.vote_round.block_round
         == current_ledger_state_->top_block_info.height + 1);

  auto has_same_proposals =
      std::all_of(std::next(msg.votes.begin()),
                  msg.votes.end(),
                  [first = msg.votes.begin()](const auto &current) {
                    return first->hash.vote_hashes.proposal_hash
                        == current.hash.vote_hashes.proposal_hash;
                  });
  if (not has_same_proposals) {
    log_->info("Proposal reject since all hashes are different");
    return ProposalReject(
        hash.vote_round, current_ledger_state_, std::move(public_keys));
  }
  log_->info("Block reject since proposal hashes match");
  return BlockReject(
      hash.vote_round, current_ledger_state_, std::move(public_keys));
}

std::optional<iroha::consensus::GateObject> YacGateImpl::handleFuture(
    const FutureMessage &msg) {
  const auto hash = getHash(msg.votes).value();
  auto public_keys = getPublicKeys(msg.votes);
  if (hash.vote_round.block_round <= current_hash_.vote_round.block_round) {
    log_->info(
        "Current block round {} is not lower than future block round {}, "
        "skipped",
        current_hash_.vote_round.block_round,
        hash.vote_round.block_round);
    return std::nullopt;
  }

  if (current_ledger_state_->top_block_info.height + 1
      >= hash.vote_round.block_round) {
    log_->info(
        "Difference between top height {} and future block round {} is "
        "less than 2, skipped",
        current_ledger_state_->top_block_info.height,
        hash.vote_round.block_round);
    return std::nullopt;
  }

  assert(hash.vote_round.block_round > current_hash_.vote_round.block_round);

  log_->info("Message from future, waiting for sync");
  return Future(hash.vote_round, current_ledger_state_, std::move(public_keys));
}
