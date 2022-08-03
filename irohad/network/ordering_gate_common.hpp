/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ORDERING_GATE_COMMON_HPP
#define IROHA_ORDERING_GATE_COMMON_HPP

#include <memory>
#include <optional>
#include <tuple>

#include "ametsuchi/ledger_state.hpp"
#include "consensus/round.hpp"

namespace shared_model {
  namespace interface {
    class Proposal;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace network {

    /**
     * Event, which is emitted by ordering gate, when it requests a proposal
     */
    struct OrderingEvent {
      std::optional<std::shared_ptr<const shared_model::interface::Proposal>>
          proposal;
      consensus::Round round;
      std::shared_ptr<const LedgerState> ledger_state;
    };

    std::shared_ptr<const shared_model::interface::Proposal> getProposalUnsafe(
        const OrderingEvent &event);

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_ORDERING_GATE_COMMON_HPP
