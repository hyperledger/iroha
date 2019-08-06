/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/kick_out_proposal_creation_strategy.hpp"

#include <utility>

using namespace iroha::ordering;

KickOutProposalCreationStrategy::KickOutProposalCreationStrategy(
    std::shared_ptr<SupermajorityCheckerType> tolerance_checker)
    : tolerance_checker_(std::move(tolerance_checker)) {}

void KickOutProposalCreationStrategy::onCollaborationOutcome(
    RoundType round, size_t peers_in_round) {
  std::lock_guard<std::mutex> guard(mutex_);
  peers_in_round_ = peers_in_round;
  while (not requested_count_.empty()
         and requested_count_.begin()->first <= round) {
    requested_count_.erase(requested_count_.begin());
  }
}

bool KickOutProposalCreationStrategy::shouldCreateRound(RoundType round) {
  std::lock_guard<std::mutex> guard(mutex_);
  return not tolerance_checker_->isTolerated(requested_count_[round],
                                             peers_in_round_);
}

boost::optional<ProposalCreationStrategy::RoundType>
KickOutProposalCreationStrategy::onProposalRequest(RoundType requested_round) {
  {
    std::lock_guard<std::mutex> guard(mutex_);
    requested_count_[requested_round]++;
  }

  return boost::none;
}
