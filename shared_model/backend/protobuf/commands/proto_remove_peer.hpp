/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_REMOVE_PEER_HPP
#define IROHA_PROTO_REMOVE_PEER_HPP

#include "interfaces/commands/remove_peer.hpp"

#include "backend/protobuf/common_objects/peer.hpp"
#include "commands.pb.h"
#include "common/result.hpp"

namespace shared_model {
  namespace proto {

    class RemovePeer final : public interface::RemovePeer {
     public:
      static iroha::expected::Result<std::unique_ptr<RemovePeer>, std::string>
      create(iroha::protocol::Command &command);

      RemovePeer(shared_model::interface::types::PubkeyType pubkey);

      const interface::types::PubkeyType &pubkey() const override;

     private:
      const interface::types::PubkeyType pubkey_;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_REMOVE_PEER_HPP
