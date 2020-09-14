/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONSENSUS_OUTCOME_DELAY_HPP
#define IROHA_CONSENSUS_OUTCOME_DELAY_HPP

#include <chrono>
#include <cstdint>

#include "consensus/yac/consensus_outcome_type.hpp"

namespace iroha::consensus::yac {

  class ConsensusOutcomeDelay {
   public:
    ConsensusOutcomeDelay(std::chrono::milliseconds max_rounds_delay);

    std::chrono::milliseconds operator()(ConsensusOutcomeType type);

   private:
    std::chrono::milliseconds const max_rounds_delay_;
    std::chrono::milliseconds const delay_increment_;
    std::chrono::milliseconds reject_delay_;
    uint64_t const max_local_counter_;
    uint64_t local_counter_;
  };

}  // namespace iroha::consensus::yac

#endif  // IROHA_CONSENSUS_OUTCOME_DELAY_HPP
