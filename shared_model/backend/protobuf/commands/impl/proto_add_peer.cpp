/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_add_peer.hpp"

namespace shared_model {
  namespace proto {

    AddPeer::AddPeer(iroha::protocol::Command &command)
        : add_peer_{command.add_peer()},
          peer_{*command.mutable_add_peer()->mutable_peer()} {}

    const interface::Peer &AddPeer::peer() const {
      return peer_;
    }

  }  // namespace proto
}  // namespace shared_model
