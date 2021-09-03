/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CONSENSUS_GATE_HPP
#define IROHA_CONSENSUS_GATE_HPP

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
      /**
       * Vote for given block creator event in consensus
       */
      virtual void vote(const simulator::BlockCreatorEvent &event) = 0;

      /// Prevent any new outgoing network activity. Be passive.
      virtual void stop() = 0;

      virtual ~ConsensusGate() = default;
    };

  }  // namespace network
}  // namespace iroha

#endif  // IROHA_CONSENSUS_GATE_HPP
