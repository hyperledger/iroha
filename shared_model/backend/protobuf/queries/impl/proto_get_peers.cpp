/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_peers.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetPeers::GetPeers(QueryType &&query)
        : CopyableProto(std::forward<QueryType>(query)) {}

    template GetPeers::GetPeers(GetPeers::TransportType &);
    template GetPeers::GetPeers(const GetPeers::TransportType &);
    template GetPeers::GetPeers(GetPeers::TransportType &&);

    GetPeers::GetPeers(const GetPeers &o) : GetPeers(o.proto_) {}

    GetPeers::GetPeers(GetPeers &&o) noexcept : GetPeers(std::move(o.proto_)) {}

  }  // namespace proto
}  // namespace shared_model
