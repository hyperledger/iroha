/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PEER_QUERY_FACTORY_HPP
#define IROHA_PEER_QUERY_FACTORY_HPP

#include <optional>

#include "ametsuchi/peer_query.hpp"

namespace iroha {
  namespace ametsuchi {
    class PeerQueryFactory {
     public:
      /**
       * Creates a peer query from the current state.
       * @return Created peer query
       */
      virtual std::optional<std::shared_ptr<PeerQuery>> createPeerQuery()
          const = 0;

      virtual ~PeerQueryFactory() = default;
    };
  }  // namespace ametsuchi
}  // namespace iroha
#endif  // IROHA_PEER_QUERY_FACTORY_HPP
