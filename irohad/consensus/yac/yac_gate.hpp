/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_GATE_HPP
#define IROHA_YAC_GATE_HPP

#include <rxcpp/rx.hpp>
#include "consensus/yac/cluster_order.hpp"
#include "consensus/yac/storage/storage_result.hpp"
#include "network/consensus_gate.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      class YacHash;
      class ClusterOrdering;

      class YacGate : public network::ConsensusGate {};

      /**
       * Provide gate for ya consensus
       */
      class HashGate {
       public:
        /**
         * Proposal new hash in network
         * @param hash - hash for voting
         * @param order - peer ordering
         */
        virtual void vote(YacHash hash, ClusterOrdering order) = 0;

        /**
         * Observable with consensus outcomes - commits and rejects - in network
         * @return observable for subscription
         */
        virtual rxcpp::observable<Answer> onOutcome() = 0;

        virtual ~HashGate() = default;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_YAC_GATE_HPP
