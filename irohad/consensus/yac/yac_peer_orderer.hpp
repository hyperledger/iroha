/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_YAC_PEER_ORDERER_HPP
#define IROHA_YAC_PEER_ORDERER_HPP

#include <boost/optional.hpp>

#include "consensus/yac/cluster_order.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      class YacHash;

      /**
       * Interface responsible for creating order for yac consensus
       */
      class YacPeerOrderer {
       public:
        /**
         * Provide order of peers based on hash and initial order of peers
         * @param hash - hash-object that used as seed of ordering shuffle
         * @param peers - an ordered list of peers
         * @return shuffled cluster order
         */
        virtual boost::optional<ClusterOrdering> getOrdering(
            const YacHash &hash,
            std::vector<std::shared_ptr<shared_model::interface::Peer>>
                peers) = 0;

        virtual ~YacPeerOrderer() = default;
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_YAC_PEER_ORDERER_HPP
