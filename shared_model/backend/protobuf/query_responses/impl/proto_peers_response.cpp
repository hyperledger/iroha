/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_peers_response.hpp"

namespace shared_model {
  namespace proto {

    PeersResponse::PeersResponse(iroha::protocol::QueryResponse &query_response)
        : peers_response_{query_response.peers_response()},
          peers_{
              query_response.mutable_peers_response()->mutable_peers()->begin(),
              query_response.mutable_peers_response()->mutable_peers()->end()} {
    }

    interface::PeersForwardCollectionType PeersResponse::peers() const {
      return peers_;
    }

  }  // namespace proto
}  // namespace shared_model
