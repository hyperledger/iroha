/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_remove_peer.hpp"

namespace shared_model {
  namespace proto {

    RemovePeer::RemovePeer(iroha::protocol::Command &command)
        : remove_peer_{command.remove_peer()} {}

    const std::string &RemovePeer::pubkey() const {
      return remove_peer_.public_key();
    }

  }  // namespace proto
}  // namespace shared_model
