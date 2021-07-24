/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/buffered_cleanup_strategy.hpp"

#include "common/visitor.hpp"

using iroha::consensus::yac::BufferedCleanupStrategy;

boost::optional<iroha::consensus::yac::CleanupStrategy::RoundsType>
BufferedCleanupStrategy::finalize(RoundType consensus_round, Answer answer) {
  using OptRefRoundType = boost::optional<RoundType> &;
  auto &target_round = iroha::visit_in_place(
      answer,
      [this](const iroha::consensus::yac::CommitMessage &) -> OptRefRoundType {
        // greater commit removes last reject because previous rejects are not
        // required anymore for the consensus
        if (last_commit_round_ and last_reject_round_
            and *last_commit_round_ < *last_reject_round_) {
          last_reject_round_ = boost::none;
        }
        return last_commit_round_;
      },
      [this](const auto &) -> OptRefRoundType { return last_reject_round_; });

  if (not target_round or *target_round < consensus_round) {
    target_round = consensus_round;
  }

  auto removed_rounds = truncateCreatedRounds();
  if (removed_rounds.empty()) {
    return boost::none;
  } else {
    return removed_rounds;
  }
}

iroha::consensus::yac::CleanupStrategy::RoundsType
BufferedCleanupStrategy::truncateCreatedRounds() {
  CleanupStrategy::RoundsType removed;
  if (last_commit_round_) {
    while (*last_commit_round_ > created_rounds_.top()) {
      removed.push_back(created_rounds_.top());
      created_rounds_.pop();
    }
  }
  return removed;
}

boost::optional<BufferedCleanupStrategy::RoundType>
BufferedCleanupStrategy::minimalRound() const {
  // both values unavailable
  if (not last_reject_round_ and not last_commit_round_) {
    return boost::none;
  }

  // both values present
  if (last_commit_round_ and last_reject_round_) {
    return std::min(*last_commit_round_, *last_reject_round_);
  }

  // one value present
  return last_commit_round_ ? last_commit_round_ : last_reject_round_;
}

bool BufferedCleanupStrategy::shouldCreateRound(const Round &round) {
  if (isRequiredCreation(round)) {
    createRound(round);
    return true;
  } else {
    return false;
  }
}

void BufferedCleanupStrategy::createRound(const Round &round) {
  created_rounds_.push(round);
}

bool BufferedCleanupStrategy::isRequiredCreation(const Round &round) const {
  // TODO: 13/12/2018 @muratovv possible DOS-attack on consensus IR-128
  auto min_round = minimalRound();
  if (min_round) {
    return *min_round <= round;
  } else {
    return true;
  }
}
