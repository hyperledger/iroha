/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "consensus/yac/impl/supermajority_checker_bft.hpp"

#include <boost/range/algorithm/max_element.hpp>
#include <boost/range/numeric.hpp>
#include "consensus/yac/impl/supermajority_checker_kf1.hpp"

using iroha::consensus::yac::SupermajorityCheckerBft;

bool SupermajorityCheckerBft::hasSupermajority(PeersNumberType agreed,
                                               PeersNumberType all) const {
  return checkKfPlus1Supermajority(
      agreed, all, detail::kSupermajorityCheckerKfPlus1Bft);
}

bool SupermajorityCheckerBft::isTolerated(PeersNumberType number,
                                          PeersNumberType all) const {
  return checkKfPlus1Tolerance(
      number, all, detail::kSupermajorityCheckerKfPlus1Bft);
}

bool SupermajorityCheckerBft::canHaveSupermajority(const VoteGroups &votes,
                                                   PeersNumberType all) const {
  const PeersNumberType largest_group =
      boost::empty(votes) ? 0 : *boost::max_element(votes);
  const PeersNumberType voted = boost::accumulate(votes, 0);
  const PeersNumberType not_voted = all - voted;

  return hasSupermajority(largest_group + not_voted, all);
}
