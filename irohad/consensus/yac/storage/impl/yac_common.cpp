/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/storage/yac_common.hpp"

#include <algorithm>

#include "consensus/yac/outcome_messages.hpp"

namespace yac = iroha::consensus::yac;

bool yac::sameKeys(const std::vector<VoteMessage> &votes) {
  if (votes.empty()) {
    return false;
  }

  auto first = votes.at(0);
  return std::all_of(votes.begin(), votes.end(), [&first](const auto &current) {
    return first.hash.vote_round == current.hash.vote_round;
  });
}

boost::optional<iroha::consensus::Round> yac::getKey(
    const std::vector<VoteMessage> &votes) {
  if (not sameKeys(votes)) {
    return boost::none;
  }
  return votes[0].hash.vote_round;
}

boost::optional<iroha::consensus::yac::YacHash> yac::getHash(
    const std::vector<VoteMessage> &votes) {
  if (not sameKeys(votes)) {
    return boost::none;
  }

  return votes.at(0).hash;
}
