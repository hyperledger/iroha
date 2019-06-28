/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/query_responses/peers_response.hpp"
#include "interfaces/common_objects/peer.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    std::string PeersResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("PeersResponse")
          .appendAll(
              peers(),
              [](std::shared_ptr<Peer> peer) { return peer->toString(); })
          .finalize();
    }

    bool PeersResponse::operator==(const ModelType &rhs) const {
      return peers() == rhs.peers();
    }

  }  // namespace interface
}  // namespace shared_model
