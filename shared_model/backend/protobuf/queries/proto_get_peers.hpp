/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_PEERS_HPP
#define IROHA_PROTO_GET_PEERS_HPP

#include "interfaces/queries/get_peers.hpp"

namespace shared_model {
  namespace proto {
    class GetPeers final : public interface::GetPeers {};

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_PEERS_HPP
