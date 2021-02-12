/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_TYPES_HPP
#define IROHA_YAC_TYPES_HPP

#include <cstddef>
#include "consensus/round.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      /// Type for number of peers in round.
      using PeersNumberType = size_t;

      struct FreezedRound {
        Round round;
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_TYPES_HPP
