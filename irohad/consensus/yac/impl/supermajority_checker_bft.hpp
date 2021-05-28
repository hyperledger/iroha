/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUPERMAJORITY_CHECKER_BFT_HPP
#define IROHA_SUPERMAJORITY_CHECKER_BFT_HPP

#include "consensus/yac/supermajority_checker.hpp"

namespace iroha::consensus::yac {
  namespace detail {
    /// The free parameter of Kf+1 consistency model for BFT.
    constexpr unsigned int kSupermajorityCheckerKfPlus1Bft = 3;
  }  // namespace detail

  /// An implementation of BFT supermajority checker.
  class SupermajorityCheckerBft : public SupermajorityChecker {
   public:
    bool hasSupermajority(PeersNumberType current,
                          PeersNumberType all) const override;

    bool isTolerated(PeersNumberType number,
                     PeersNumberType all) const override;

    bool canHaveSupermajority(const VoteGroups &votes,
                              PeersNumberType all) const override;
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_SUPERMAJORITY_CHECKER_BFT_HPP
