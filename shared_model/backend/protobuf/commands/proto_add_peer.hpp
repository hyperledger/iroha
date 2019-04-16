/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ADD_PEER_HPP
#define IROHA_PROTO_ADD_PEER_HPP

#include "backend/protobuf/common_objects/peer.hpp"
#include "commands.pb.h"
#include "interfaces/commands/add_peer.hpp"
#include "interfaces/common_objects/peer.hpp"

namespace shared_model {
  namespace proto {

    class AddPeer final : public CopyableProto<interface::AddPeer,
                                               iroha::protocol::Command,
                                               AddPeer> {
     public:
      template <typename CommandType>
      explicit AddPeer(CommandType &&command);

      AddPeer(const AddPeer &o);

      AddPeer(AddPeer &&o) noexcept;

      const interface::Peer &peer() const override;

     private:
      const iroha::protocol::AddPeer &add_peer_;
      const proto::Peer peer_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ADD_PEER_HPP
