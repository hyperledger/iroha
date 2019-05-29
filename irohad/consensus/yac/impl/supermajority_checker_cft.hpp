/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUPERMAJORITY_CHECKER_CFT_HPP
#define IROHA_SUPERMAJORITY_CHECKER_CFT_HPP

#include "consensus/yac/supermajority_checker.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      namespace detail {
        /// The free parameter of Kf+1 consistency model for CFT.
        constexpr unsigned int kSupermajorityCheckerKfPlus1Cft = 2;
      }  // namespace detail

      /// An implementation of CFT supermajority checker.
      class SupermajorityCheckerCft : public SupermajorityChecker {
       public:
        bool hasSupermajority(PeersNumberType current,
                              PeersNumberType all) const override;

        bool isTolerated(PeersNumberType number,
                         PeersNumberType all) const override;

        bool canHaveSupermajority(const VoteGroups &votes,
                                  PeersNumberType all) const override;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_SUPERMAJORITY_CHECKER_CFT_HPP
