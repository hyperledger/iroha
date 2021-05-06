/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "ordering/impl/on_demand_common.hpp"

namespace iroha {
  namespace ordering {

    const consensus::RejectRoundType kFirstRejectRound = 0;

    consensus::Round nextCommitRound(const consensus::Round &round) {
      return {round.block_round + 1, kFirstRejectRound};
    }

    consensus::Round nextRejectRound(const consensus::Round &round) {
      return {round.block_round, round.reject_round + 1};
    }

  }  // namespace ordering
}  // namespace iroha
