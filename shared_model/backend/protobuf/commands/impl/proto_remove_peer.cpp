/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_remove_peer.hpp"

namespace shared_model {
  namespace proto {

    RemovePeer::RemovePeer(iroha::protocol::Command &command)
        : pubkey_{crypto::Hash::fromHexString(
              command.remove_peer().public_key())} {}

    const interface::types::PubkeyType &RemovePeer::pubkey() const {
      return pubkey_;
    }

  }  // namespace proto
}  // namespace shared_model
