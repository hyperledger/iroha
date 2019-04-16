/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_COMMON_HPP
#define IROHA_ON_DEMAND_COMMON_HPP

#include "consensus/round.hpp"

namespace iroha {
  namespace ordering {

    extern const consensus::RejectRoundType kFirstRejectRound;

    consensus::RejectRoundType currentRejectRoundConsumer(
        consensus::RejectRoundType round);

    extern const consensus::RejectRoundType kNextRejectRoundConsumer;

    extern const consensus::RejectRoundType kNextCommitRoundConsumer;

    consensus::Round nextCommitRound(const consensus::Round &round);

    consensus::Round nextRejectRound(const consensus::Round &round);

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_COMMON_HPP
