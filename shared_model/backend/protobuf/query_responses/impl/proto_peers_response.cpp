/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_peers_response.hpp"

#include <boost/range/numeric.hpp>
#include "backend/protobuf/common_objects/peer.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    PeersResponse::PeersResponse(QueryResponseType &&query_response)
        : CopyableProto(std::forward<QueryResponseType>(query_response)),
          peers_response_{proto_->peers_response()},
          peers_{boost::accumulate(peers_response_.peers(),
                                   interface::types::PeerList{},
                                   [](auto &&peers, const auto &peer) {
                                     peers.push_back(
                                         std::make_shared<Peer>(peer));
                                     return std::move(peers);
                                   })} {}

    template PeersResponse::PeersResponse(PeersResponse::TransportType &);
    template PeersResponse::PeersResponse(const PeersResponse::TransportType &);
    template PeersResponse::PeersResponse(PeersResponse::TransportType &&);

    PeersResponse::PeersResponse(const PeersResponse &o)
        : PeersResponse(o.proto_) {}

    PeersResponse::PeersResponse(PeersResponse &&o)
        : PeersResponse(std::move(o.proto_)) {}

    const interface::types::PeerList &PeersResponse::peers() const {
      return peers_;
    }

  }  // namespace proto
}  // namespace shared_model
