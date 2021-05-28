/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/yac_proposal_storage.hpp"

#include <boost/range/adaptor/transformed.hpp>
#include "logger/logger.hpp"
#include "logger/logger_manager.hpp"

using iroha::consensus::yac::YacProposalStorage;

// --------| private api |--------

auto YacProposalStorage::findStore(const YacHash &store_hash) {
  // find exist
  auto iter = std::find_if(block_storages_.begin(),
                           block_storages_.end(),
                           [&store_hash](auto block_storage) {
                             auto storage_key = block_storage.getStorageKey();
                             return storage_key == store_hash;
                           });
  if (iter != block_storages_.end()) {
    return iter;
  }
  // insert and return new
  return block_storages_.emplace(
      block_storages_.end(),
      YacHash(store_hash.vote_round,
              store_hash.vote_hashes.proposal_hash,
              store_hash.vote_hashes.block_hash),
      peers_in_round_,
      supermajority_checker_,
      log_manager_->getChild("BlockStorage")->getLogger());
}

// --------| public api |--------

YacProposalStorage::YacProposalStorage(
    Round store_round,
    PeersNumberType peers_in_round,
    std::shared_ptr<SupermajorityChecker> supermajority_checker,
    logger::LoggerManagerTreePtr log_manager)
    : current_state_(boost::none),
      storage_key_(store_round),
      peers_in_round_(peers_in_round),
      supermajority_checker_(supermajority_checker),
      log_manager_(std::move(log_manager)),
      log_(log_manager_->getLogger()) {}

boost::optional<iroha::consensus::yac::Answer> YacProposalStorage::insert(
    VoteMessage msg) {
  if (shouldInsert(msg)) {
    // insert to block store

    log_->info("Vote with {} and hashes [{}, {}] looks valid",
               msg.hash.vote_round,
               msg.hash.vote_hashes.proposal_hash,
               msg.hash.vote_hashes.block_hash);

    auto iter = findStore(msg.hash);
    auto block_state = iter->insert(msg);

    // Single BlockStorage always returns CommitMessage because it
    // aggregates votes for a single hash.
    if (block_state) {
      // supermajority on block achieved
      current_state_ = std::move(block_state);
    } else {
      // try to find reject case
      auto reject_state = findRejectProof();
      if (reject_state) {
        log_->info("Found reject proof");
        current_state_ = std::move(reject_state);
      }
    }
  }
  return getState();
}

boost::optional<iroha::consensus::yac::Answer> YacProposalStorage::insert(
    std::vector<VoteMessage> messages) {
  for (auto &vote : messages) {
    insert(std::move(vote));
  }
  return getState();
}

const iroha::consensus::Round &YacProposalStorage::getStorageKey() const {
  return storage_key_;
}

boost::optional<iroha::consensus::yac::Answer> YacProposalStorage::getState()
    const {
  return current_state_;
}

// --------| private api |--------

bool YacProposalStorage::shouldInsert(const VoteMessage &msg) {
  return checkProposalRound(msg.hash.vote_round) and checkPeerUniqueness(msg);
}

bool YacProposalStorage::checkProposalRound(const Round &vote_round) {
  return vote_round == storage_key_;
}

bool YacProposalStorage::checkPeerUniqueness(const VoteMessage &msg) {
  return std::all_of(block_storages_.begin(),
                     block_storages_.end(),
                     [&msg](YacBlockStorage &storage) {
                       if (storage.getStorageKey() != msg.hash) {
                         return true;
                       }
                       return not storage.isContains(msg);
                     });
}

boost::optional<iroha::consensus::yac::Answer>
YacProposalStorage::findRejectProof() {
  auto is_reject = not supermajority_checker_->canHaveSupermajority(
      block_storages_ | boost::adaptors::transformed([](const auto &storage) {
        return storage.getNumberOfVotes();
      }),
      peers_in_round_);

  if (is_reject) {
    std::vector<VoteMessage> result;
    std::for_each(block_storages_.begin(),
                  block_storages_.end(),
                  [&result](auto &storage) {
                    auto votes_from_block_storage = storage.getVotes();
                    std::move(votes_from_block_storage.begin(),
                              votes_from_block_storage.end(),
                              std::back_inserter(result));
                  });

    return Answer(RejectMessage(std::move(result)));
  }

  return boost::none;
}
