/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUPERMAJORITY_CHECKER_KF1_HPP
#define IROHA_SUPERMAJORITY_CHECKER_KF1_HPP

#include "consensus/yac/supermajority_checker.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      /**
       * A generic implementation of N = K * f + 1 supermajority checker.
       * N is the amount of peers in the network, f is the number of tolerated
       * faulty peers, and K is a free parameter. Supermajority is achieved when
       * at least N - f peers agree. For the networks of arbitrary peers amount
       * Na the tolerated number of faulty peers is (Na - 1) % K.
       *
       * @param agreed - the number of peers agreed on the state
       * @param all - the total number of peers in the network
       * @param k - the free parameter of the model
       *
       * @return whether supermajority is achieved by the agreed peers
       */
      inline bool checkKfPlus1Supermajority(PeersNumberType agreed,
                                            PeersNumberType all,
                                            unsigned int k) {
        if (agreed > all) {
          return false;
        }
        return agreed * k >= (k - 1) * (all - 1) + k;
      }

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_SUPERMAJORITY_CHECKER_KF1_HPP
