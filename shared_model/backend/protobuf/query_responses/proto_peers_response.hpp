/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PEERS_RESPONSE_HPP
#define IROHA_SHARED_MODEL_PROTO_PEERS_RESPONSE_HPP

#include "backend/protobuf/common_objects/peer.hpp"
#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/query_responses/peers_response.hpp"
#include "qry_responses.pb.h"

namespace shared_model {
  namespace proto {
    class PeersResponse final
        : public CopyableProto<interface::PeersResponse,
                               iroha::protocol::QueryResponse,
                               PeersResponse> {
     public:
      template <typename QueryResponseType>
      explicit PeersResponse(QueryResponseType &&query_response);

      PeersResponse(const PeersResponse &o);

      PeersResponse(PeersResponse &&o);

      interface::PeersForwardCollectionType peers() const override;

     private:
      const iroha::protocol::PeersResponse &peers_response_;

      const std::vector<Peer> peers_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_PEERS_RESPONSE_HPP
