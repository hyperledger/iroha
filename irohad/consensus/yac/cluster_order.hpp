/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_CLUSTER_ORDER_HPP
#define IROHA_CLUSTER_ORDER_HPP

#include <memory>
#include <vector>

#include <boost/optional.hpp>
#include "consensus/yac/yac_types.hpp"
#include "interfaces/common_objects/types.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      /**
       * Class provide ordering on cluster for current round
       */
      class ClusterOrdering {
       public:
        /**
         * Creates cluster ordering from the vector of peers
         * @param order vector of peers
         * @return false if vector is empty, true otherwise
         */
        static boost::optional<ClusterOrdering> create(
            const std::vector<std::shared_ptr<shared_model::interface::Peer>>
                &order);

        /**
         * Provide current leader peer
         */
        const shared_model::interface::Peer &currentLeader();

        /**
         * Switch to next peer as leader
         * @return this
         */
        ClusterOrdering &switchToNext();

        /**
         * @return true if current leader not last peer in order
         */
        bool hasNext() const;

        const shared_model::interface::types::PeerList &getPeers() const;

        PeersNumberType getNumberOfPeers() const;

        virtual ~ClusterOrdering() = default;

        ClusterOrdering() = delete;

       private:
        // prohibit creation of the object not from create method
        explicit ClusterOrdering(
            std::vector<std::shared_ptr<shared_model::interface::Peer>> order);

        std::vector<std::shared_ptr<shared_model::interface::Peer>> order_;
        PeersNumberType index_ = 0;
      };
    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha
#endif  // IROHA_CLUSTER_ORDER_HPP
