/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_PEER_ORDERER_HPP
#define IROHA_MOCK_YAC_PEER_ORDERER_HPP

#include <gmock/gmock.h>

#include "consensus/yac/yac_peer_orderer.hpp"

namespace iroha {
  namespace consensus {
    namespace yac {

      class MockYacPeerOrderer : public YacPeerOrderer {
       public:
        MOCK_METHOD2(
            getOrdering,
            boost::optional<ClusterOrdering>(
                const YacHash &,
                std::vector<std::shared_ptr<shared_model::interface::Peer>>));

        MockYacPeerOrderer() = default;

        MockYacPeerOrderer(const MockYacPeerOrderer &rhs){};

        MockYacPeerOrderer(MockYacPeerOrderer &&rhs){};

        MockYacPeerOrderer &operator=(const MockYacPeerOrderer &rhs) {
          return *this;
        }
      };

    }  // namespace yac
  }    // namespace consensus
}  // namespace iroha

#endif  // IROHA_MOCK_YAC_PEER_ORDERER_HPP
