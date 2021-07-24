/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/supermajority_checker_cft.hpp"

#include <boost/range/algorithm/max_element.hpp>
#include <boost/range/numeric.hpp>
#include "consensus/yac/impl/supermajority_checker_kf1.hpp"

using iroha::consensus::yac::SupermajorityCheckerCft;

bool SupermajorityCheckerCft::hasSupermajority(PeersNumberType agreed,
                                               PeersNumberType all) const {
  return checkKfPlus1Supermajority(
      agreed, all, detail::kSupermajorityCheckerKfPlus1Cft);
}

bool SupermajorityCheckerCft::isTolerated(PeersNumberType number,
                                          PeersNumberType all) const {
  return checkKfPlus1Tolerance(
      number, all, detail::kSupermajorityCheckerKfPlus1Cft);
}

bool SupermajorityCheckerCft::canHaveSupermajority(const VoteGroups &votes,
                                                   PeersNumberType all) const {
  const PeersNumberType largest_group =
      boost::empty(votes) ? 0 : *boost::max_element(votes);
  const PeersNumberType voted = boost::accumulate(votes, 0);
  const PeersNumberType not_voted = all - voted;

  return hasSupermajority(largest_group + not_voted, all);
}
