/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_add_peer.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    AddPeer::AddPeer(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          add_peer_{proto_->add_peer()},
          peer_{*proto_->mutable_add_peer()->mutable_peer()} {}

    template AddPeer::AddPeer(AddPeer::TransportType &);
    template AddPeer::AddPeer(const AddPeer::TransportType &);
    template AddPeer::AddPeer(AddPeer::TransportType &&);

    AddPeer::AddPeer(const AddPeer &o) : AddPeer(o.proto_) {}

    AddPeer::AddPeer(AddPeer &&o) noexcept : AddPeer(std::move(o.proto_)) {}

    const interface::Peer &AddPeer::peer() const {
      return peer_;
    }

  }  // namespace proto
}  // namespace shared_model
