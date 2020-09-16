/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/consensus_outcome_delay.hpp"

#include <algorithm>
#include <ciso646>

using namespace iroha::consensus::yac;

ConsensusOutcomeDelay::ConsensusOutcomeDelay(
    std::chrono::milliseconds max_rounds_delay)
    : max_rounds_delay_(max_rounds_delay),
      delay_increment_(
          std::min(max_rounds_delay_, std::chrono::milliseconds(1000))),
      reject_delay_(0),
      max_local_counter_(2),
      local_counter_(0) {}

std::chrono::milliseconds ConsensusOutcomeDelay::operator()(
    ConsensusOutcomeType type) {
  if (type == ConsensusOutcomeType::kReject
      or type == ConsensusOutcomeType::kNothing) {
    // Increment reject_counter each local_counter calls of function
    ++local_counter_;
    if (local_counter_ == max_local_counter_) {
      local_counter_ = 0;
      if (reject_delay_ < max_rounds_delay_) {
        reject_delay_ += delay_increment_;
      }
    }
  } else {
    reject_delay_ = std::chrono::milliseconds(0);
  }
  return reject_delay_;
}
