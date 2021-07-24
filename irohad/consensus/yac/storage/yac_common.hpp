/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_COMMON_HPP
#define IROHA_YAC_COMMON_HPP

#include <vector>

#include <boost/optional.hpp>

#include "consensus/round.hpp"

namespace iroha::consensus::yac {
  class YacHash;
  struct VoteMessage;

  using ProposalHash = std::string;

  using BlockHash = std::string;

  /**
   * Check that all votes in collection have the same key
   * @param votes - collection of votes
   * @return true, if rounds of those votes are the same
   */
  bool sameKeys(const std::vector<VoteMessage> &votes);

  /**
   * Provide key common for whole collection
   * @param votes - collection with votes
   * @return vote round, if collection shared the same round,
   * otherwise boost::none
   */
  boost::optional<Round> getKey(const std::vector<VoteMessage> &votes);

  /**
   * Get common hash from collection
   * @param votes - collection with votes
   * @return hash, if collection elements have same hash,
   * otherwise boost::none
   */
  boost::optional<YacHash> getHash(const std::vector<VoteMessage> &votes);

}  // namespace iroha::consensus::yac

#endif  // IROHA_YAC_COMMON_HPP
