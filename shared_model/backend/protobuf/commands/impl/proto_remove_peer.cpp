/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_remove_peer.hpp"

#include "commands.pb.h"
#include "common/result.hpp"
#include "cryptography/blob.hpp"

using shared_model::interface::types::PubkeyType;

namespace shared_model {
  namespace proto {

    iroha::expected::Result<std::unique_ptr<RemovePeer>, std::string>
    RemovePeer::create(iroha::protocol::Command &command) {
      return shared_model::crypto::Blob::fromHexString(
                 command.remove_peer().public_key())
          |
          [](auto &&pubkey) {
            return std::make_unique<RemovePeer>(PubkeyType{std::move(pubkey)});
          };
    }

    RemovePeer::RemovePeer(PubkeyType pubkey) : pubkey_(std::move(pubkey)) {}

    const PubkeyType &RemovePeer::pubkey() const {
      return pubkey_;
    }

  }  // namespace proto
}  // namespace shared_model
