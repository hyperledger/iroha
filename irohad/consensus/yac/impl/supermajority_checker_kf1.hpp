/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SUPERMAJORITY_CHECKER_KF1_HPP
#define IROHA_SUPERMAJORITY_CHECKER_KF1_HPP

#include "consensus/yac/supermajority_checker.hpp"

namespace iroha::consensus::yac {
  /**
   * A generic implementation of N = K * f + 1 model checkers.
   * N is the amount of peers in the network, f is the number of tolerated
   * faulty peers, and K is a free parameter. Supermajority is achieved when
   * at least N - f peers agree. For the networks of arbitrary peers amount
   * Na the tolerated number of faulty peers is (Na - 1) % K.
   */

  /**
   * Check supermajority condition.
   *
   * @param number - the number of peers agreed on the state
   * @param all - the total number of peers in the network
   * @param k - the free parameter of the model
   *
   * @return whether supermajority is achieved by the agreed peers
   */
  inline bool checkKfPlus1Supermajority(PeersNumberType number,
                                        PeersNumberType all,
                                        unsigned int k) {
    if (number > all) {
      return false;
    }
    return number * k >= (k - 1) * (all - 1) + k;
  }

  /**
   * Check tolerance condition.
   *
   * @param number - the number of possibly faulty peers
   * @param all - the total number of peers in the network
   * @param k - the free parameter of the model
   *
   * @return whether the given number of possibly faulty peers is tolerated
   * by the network.
   */
  inline bool checkKfPlus1Tolerance(PeersNumberType number,
                                    PeersNumberType all,
                                    unsigned int k) {
    if (number > all) {
      return false;
    }
    return number * k > all - 1;
  }
}  // namespace iroha::consensus::yac

#endif  // IROHA_SUPERMAJORITY_CHECKER_KF1_HPP
