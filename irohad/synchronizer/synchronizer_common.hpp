/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SYNCHRONIZER_COMMON_HPP
#define IROHA_SYNCHRONIZER_COMMON_HPP

#include <utility>

#include "consensus/round.hpp"

namespace iroha {
  struct LedgerState;
  namespace synchronizer {

    /**
     * Outcome, which was decided by synchronizer based on consensus result and
     * current local ledger state
     */
    enum class SynchronizationOutcomeType {
      kCommit,
      kReject,
      kNothing,
    };

    /**
     * Event, which is emitted by synchronizer, when it receives and processes
     * commit
     */
    struct SynchronizationEvent {
      SynchronizationOutcomeType sync_outcome;
      consensus::Round round;
      std::shared_ptr<const iroha::LedgerState> ledger_state;
    };

  }  // namespace synchronizer
}  // namespace iroha

#endif  // IROHA_SYNCHRONIZER_COMMON_HPP
