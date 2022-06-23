/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ON_DEMAND_COMMON_HPP
#define IROHA_ON_DEMAND_COMMON_HPP

#include <memory>
#include <optional>
#include <vector>

#include "consensus/round.hpp"

namespace shared_model::interface {
  class Proposal;
}

namespace iroha::ordering {

  extern const consensus::RejectRoundType kFirstRejectRound;
  consensus::Round nextCommitRound(const consensus::Round &round);
  consensus::Round nextRejectRound(const consensus::Round &round);

  struct ProposalEvent {
    using ProposalPack =
        std::vector<std::shared_ptr<shared_model::interface::Proposal const>>;
    ProposalPack proposal_pack;
    consensus::Round round;
  };

  using SingleProposalEvent =
      std::tuple<consensus::Round,
                 std::shared_ptr<const shared_model::interface::Proposal>>;

}  // namespace iroha::ordering

#endif  // IROHA_ON_DEMAND_COMMON_HPP
