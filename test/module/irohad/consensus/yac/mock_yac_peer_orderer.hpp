/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_YAC_PEER_ORDERER_HPP
#define IROHA_MOCK_YAC_PEER_ORDERER_HPP

#include <gmock/gmock.h>

#include "consensus/yac/yac_peer_orderer.hpp"

namespace iroha::consensus::yac {
  class MockYacPeerOrderer : public YacPeerOrderer {
   public:
    MOCK_METHOD2(
        getOrdering,
        std::optional<ClusterOrdering>(
            const YacHash &,
            std::vector<std::shared_ptr<shared_model::interface::Peer>> const
                &));

    MockYacPeerOrderer() = default;

    MockYacPeerOrderer(const MockYacPeerOrderer &rhs){};

    MockYacPeerOrderer(MockYacPeerOrderer &&rhs){};

    MockYacPeerOrderer &operator=(const MockYacPeerOrderer &rhs) {
      return *this;
    }
  };
}  // namespace iroha::consensus::yac

#endif  // IROHA_MOCK_YAC_PEER_ORDERER_HPP
