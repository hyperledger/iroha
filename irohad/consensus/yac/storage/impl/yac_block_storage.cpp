/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/yac_block_storage.hpp"

#include "logger/logger.hpp"

using iroha::consensus::yac::YacBlockStorage;

// --------| Public API |--------

YacBlockStorage::YacBlockStorage(
    YacHash hash,
    PeersNumberType peers_in_round,
    std::shared_ptr<SupermajorityChecker> supermajority_checker,
    logger::LoggerPtr log)
    : storage_key_(std::move(hash)),
      peers_in_round_(peers_in_round),
      supermajority_checker_(std::move(supermajority_checker)),
      log_(std::move(log)) {}

boost::optional<iroha::consensus::yac::Answer> YacBlockStorage::insert(
    VoteMessage msg) {
  if (validScheme(msg) and uniqueVote(msg)) {
    votes_.push_back(msg);

    log_->info(
        "Vote with round {} and hashes ({}, {}) inserted, votes in "
        "storage [{}/{}]",
        msg.hash.vote_round,
        msg.hash.vote_hashes.proposal_hash,
        msg.hash.vote_hashes.block_hash,
        votes_.size(),
        peers_in_round_);
  }
  return getState();
}

boost::optional<iroha::consensus::yac::Answer> YacBlockStorage::insert(
    std::vector<VoteMessage> votes) {
  for (auto &vote : votes) {
    insert(std::move(vote));
  }
  return getState();
}

std::vector<iroha::consensus::yac::VoteMessage> YacBlockStorage::getVotes()
    const {
  return votes_;
}

size_t YacBlockStorage::getNumberOfVotes() const {
  return votes_.size();
}

boost::optional<iroha::consensus::yac::Answer> YacBlockStorage::getState() {
  auto supermajority =
      supermajority_checker_->hasSupermajority(votes_.size(), peers_in_round_);
  if (supermajority) {
    return Answer(CommitMessage(votes_));
  }
  return boost::none;
}

bool YacBlockStorage::isContains(const VoteMessage &msg) const {
  return std::count(votes_.begin(), votes_.end(), msg) != 0;
}

iroha::consensus::yac::YacHash YacBlockStorage::getStorageKey() const {
  return storage_key_;
}

// --------| private api |--------

bool YacBlockStorage::uniqueVote(VoteMessage &msg) {
  // lookup take O(n) times
  return std::all_of(
      votes_.begin(), votes_.end(), [&msg](auto vote) { return vote != msg; });
}

bool YacBlockStorage::validScheme(VoteMessage &vote) {
  return getStorageKey() == vote.hash;
}
