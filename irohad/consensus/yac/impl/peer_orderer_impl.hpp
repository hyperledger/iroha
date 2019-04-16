/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_ORDERER_IMPL_HPP
#define IROHA_PEER_ORDERER_IMPL_HPP

#include <memory>

#include "ametsuchi/peer_query_factory.hpp"
#include "consensus/yac/yac_peer_orderer.hpp"

namespace iroha {

  namespace consensus {
    namespace yac {

      class ClusterOrdering;
      class YacHash;

      class PeerOrdererImpl : public YacPeerOrderer {
       public:
        // TODO 30.01.2019 lebdron: IR-262 Remove PeerQueryFactory
        explicit PeerOrdererImpl(
            std::shared_ptr<ametsuchi::PeerQueryFactory> peer_query_factory);

        boost::optional<ClusterOrdering> getOrdering(
            const YacHash &hash,
            std::vector<std::shared_ptr<shared_model::interface::Peer>> peers)
            override;

       private:
        std::shared_ptr<ametsuchi::PeerQueryFactory> peer_query_factory_;
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_PEER_ORDERER_IMPL_HPP
