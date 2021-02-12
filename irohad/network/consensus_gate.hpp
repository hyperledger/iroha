/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONSENSUS_GATE_HPP
#define IROHA_CONSENSUS_GATE_HPP

#include <rxcpp/rx-observable-fwd.hpp>
#include "consensus/gate_object.hpp"

namespace shared_model {
  namespace interface {
    class Block;
    class Proposal;
  }  // namespace interface
}  // namespace shared_model

namespace iroha {

  namespace simulator {
    struct BlockCreatorEvent;
  }  // namespace simulator

  namespace network {

    /**
     * Public api of consensus module
     */
    class ConsensusGate {
     public:
      using Round = consensus::Round;

      /**
       * Vote for given block creator event in consensus
       */
      virtual void vote(const simulator::BlockCreatorEvent &event) = 0;

      using GateObject = consensus::GateObject;

      /**
       * @return emit gate responses
       */
      virtual rxcpp::observable<consensus::GateObject> onOutcome() = 0;

      /**
       * Notification called when unable to wrap the round.
       * @return observable
       */
      virtual rxcpp::observable<consensus::FreezedRound> onFreezedRound() = 0;

      /// Prevent any new outgoing network activity. Be passive.
      virtual void stop() = 0;

      virtual ~ConsensusGate() = default;
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_CONSENSUS_GATE_HPP
