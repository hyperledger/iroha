/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_REMOVE_PEER_HPP
#define IROHA_PROTO_REMOVE_PEER_HPP

#include "interfaces/commands/remove_peer.hpp"

#include "backend/protobuf/common_objects/peer.hpp"
#include "commands.pb.h"

namespace shared_model {
  namespace proto {

    class RemovePeer final : public interface::RemovePeer {
     public:
      explicit RemovePeer(iroha::protocol::Command &command);

      const std::string &pubkey() const override;

     private:
      const iroha::protocol::RemovePeer &remove_peer_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_REMOVE_PEER_HPP
