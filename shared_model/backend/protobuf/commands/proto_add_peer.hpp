/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ADD_PEER_HPP
#define IROHA_PROTO_ADD_PEER_HPP

#include "interfaces/commands/add_peer.hpp"

#include "backend/protobuf/common_objects/peer.hpp"
#include "common/result_fwd.hpp"
#include "interfaces/common_objects/peer.hpp"

namespace iroha {
  namespace protocol {
    class Command;
  }
}  // namespace iroha

namespace shared_model {
  namespace proto {

    class AddPeer final : public interface::AddPeer {
     public:
      static iroha::expected::Result<std::unique_ptr<AddPeer>, std::string>
      create(iroha::protocol::Command &command);

      explicit AddPeer(proto::Peer peer);

      const interface::Peer &peer() const override;

     private:
      proto::Peer peer_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ADD_PEER_HPP
