/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_PEER_QUERY_HPP
#define IROHA_MOCK_PEER_QUERY_HPP

#include "ametsuchi/peer_query.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockPeerQuery : public PeerQuery {
     public:
      MockPeerQuery() = default;

      MOCK_METHOD1(getLedgerPeers, boost::optional<std::vector<wPeer>>(bool));

      MOCK_CONST_METHOD1(
          getLedgerPeerByPublicKey,
          boost::optional<PeerQuery::wPeer>(
              shared_model::interface::types::PublicKeyHexStringView));
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_PEER_QUERY_HPP
