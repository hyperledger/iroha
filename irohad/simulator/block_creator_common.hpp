/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BLOCK_CREATOR_COMMON_HPP
#define IROHA_BLOCK_CREATOR_COMMON_HPP

#include <memory>

#include <boost/optional.hpp>
#include "ametsuchi/ledger_state.hpp"
#include "consensus/round.hpp"

namespace shared_model {
  namespace interface {
    class Block;
    class Proposal;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {
  namespace simulator {

    struct RoundData {
      std::shared_ptr<const shared_model::interface::Proposal> proposal;
      std::shared_ptr<shared_model::interface::Block> block;
    };

    /**
     * Event, which is emitted by block creator, when it receives and processes
     * a verified proposal
     */
    struct BlockCreatorEvent {
      boost::optional<RoundData> round_data;
      consensus::Round round;
      std::shared_ptr<const LedgerState> ledger_state;
    };

    std::shared_ptr<shared_model::interface::Block> getBlockUnsafe(
        const BlockCreatorEvent &event);

  }  // namespace simulator
}  // namespace iroha

#endif  // IROHA_BLOCK_CREATOR_COMMON_HPP
