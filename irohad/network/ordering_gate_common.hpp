/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_GATE_COMMON_HPP
#define IROHA_ORDERING_GATE_COMMON_HPP

#include <memory>
#include <optional>

#include "ametsuchi/ledger_state.hpp"
#include "consensus/round.hpp"

namespace shared_model::interface {
  class Proposal;
}  // namespace shared_model::interface

namespace iroha::network {

  /**
     * Event, which is emitted by ordering gate, when it requests a proposal
   */
  struct OrderingEvent {
    using ProposalPack =
        std::vector<std::shared_ptr<shared_model::interface::Proposal const>>;

    ProposalPack proposal_pack;
    consensus::Round round;
    std::shared_ptr<const LedgerState> ledger_state;
  };

  OrderingEvent::ProposalPack const &getProposalUnsafe(
      const OrderingEvent &event);

}  // namespace iroha::network

#endif  // IROHA_ORDERING_GATE_COMMON_HPP
