/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MOCK_PEER_QUERY_FACTORY_HPP
#define IROHA_MOCK_PEER_QUERY_FACTORY_HPP

#include "ametsuchi/peer_query_factory.hpp"

#include <gmock/gmock.h>

namespace iroha {
  namespace ametsuchi {

    class MockPeerQueryFactory : public PeerQueryFactory {
     public:
      MOCK_CONST_METHOD0(createPeerQuery,
                         boost::optional<std::shared_ptr<PeerQuery>>());
    };

  }  // namespace ametsuchi
}  // namespace iroha

#endif  // IROHA_MOCK_PEER_QUERY_FACTORY_HPP
