/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_add_peer.hpp"

namespace shared_model {
  namespace proto {

    iroha::expected::Result<std::unique_ptr<AddPeer>, std::string>
    AddPeer::create(iroha::protocol::Command &command) {
      return Peer::create(*command.mutable_add_peer()->mutable_peer()) |
          [](auto &&peer) { return std::make_unique<AddPeer>(*peer); };
    }

    AddPeer::AddPeer(proto::Peer peer) : peer_(std::move(peer)) {}

    const interface::Peer &AddPeer::peer() const {
      return peer_;
    }

  }  // namespace proto
}  // namespace shared_model
