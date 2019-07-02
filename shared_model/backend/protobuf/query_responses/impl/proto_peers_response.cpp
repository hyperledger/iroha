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
          peers_{proto_->mutable_peers_response()->mutable_peers()->begin(),
                 proto_->mutable_peers_response()->mutable_peers()->end()} {}

    template PeersResponse::PeersResponse(PeersResponse::TransportType &);
    template PeersResponse::PeersResponse(const PeersResponse::TransportType &);
    template PeersResponse::PeersResponse(PeersResponse::TransportType &&);

    PeersResponse::PeersResponse(const PeersResponse &o)
        : PeersResponse(o.proto_) {}

    PeersResponse::PeersResponse(PeersResponse &&o)
        : PeersResponse(std::move(o.proto_)) {}

    interface::PeersForwardCollectionType PeersResponse::peers() const {
      return peers_;
    }

  }  // namespace proto
}  // namespace shared_model
