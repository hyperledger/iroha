/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_remove_signatory.hpp"

#include "commands.pb.h"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"

using shared_model::interface::types::PubkeyType;

namespace shared_model {
  namespace proto {

    iroha::expected::Result<std::unique_ptr<RemoveSignatory>, std::string>
    RemoveSignatory::create(iroha::protocol::Command &command) {
      return shared_model::crypto::Blob::fromHexString(
                 command.remove_signatory().public_key())
          | [&](auto &&pubkey) {
              return std::make_unique<RemoveSignatory>(
                  command, PubkeyType{std::move(pubkey)});
            };
    }

    RemoveSignatory::RemoveSignatory(iroha::protocol::Command &command,
                                     PubkeyType pubkey)
        : remove_signatory_{command.remove_signatory()},
          pubkey_(std::move(pubkey)) {}

    const interface::types::AccountIdType &RemoveSignatory::accountId() const {
      return remove_signatory_.account_id();
    }

    const PubkeyType &RemoveSignatory::pubkey() const {
      return pubkey_;
    }

  }  // namespace proto
}  // namespace shared_model
