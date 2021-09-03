/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ROUND_SWITCH_HPP
#define IROHA_ROUND_SWITCH_HPP

#include <memory>

#include "consensus/round.hpp"

namespace iroha {
  struct LedgerState;
}

namespace iroha::ordering {
  struct RoundSwitch {
    consensus::Round next_round;
    std::shared_ptr<const LedgerState> ledger_state;

    RoundSwitch(consensus::Round next_round,
                std::shared_ptr<const LedgerState> ledger_state)
        : next_round(std::move(next_round)),
          ledger_state(std::move(ledger_state)) {}
  };
}  // namespace iroha::ordering

#endif  // IROHA_ROUND_SWITCH_HPP
