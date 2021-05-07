/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_COMMON_HPP
#define IROHA_ON_DEMAND_COMMON_HPP

#include <memory>
#include <optional>

#include "consensus/round.hpp"

namespace shared_model::interface {
  class Proposal;
}

namespace iroha {
  namespace ordering {

    extern const consensus::RejectRoundType kFirstRejectRound;

    consensus::Round nextCommitRound(const consensus::Round &round);

    consensus::Round nextRejectRound(const consensus::Round &round);

    struct ProposalEvent {
      std::optional<std::shared_ptr<const shared_model::interface::Proposal>>
          proposal;
      consensus::Round round;
    };

  }  // namespace ordering
}  // namespace iroha

#endif  // IROHA_ON_DEMAND_COMMON_HPP
