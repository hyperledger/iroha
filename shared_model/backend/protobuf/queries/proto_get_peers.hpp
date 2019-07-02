/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_PEERS_HPP
#define IROHA_PROTO_GET_PEERS_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/get_peers.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetPeers final : public CopyableProto<interface::GetPeers,
                                                iroha::protocol::Query,
                                                GetPeers> {
     public:
      template <typename QueryType>
      explicit GetPeers(QueryType &&query);

      GetPeers(const GetPeers &o);

      GetPeers(GetPeers &&o) noexcept;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_PEERS_HPP
