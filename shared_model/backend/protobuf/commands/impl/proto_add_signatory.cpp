/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_add_signatory.hpp"

#include "commands.pb.h"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"

using shared_model::interface::types::PubkeyType;

namespace shared_model {
  namespace proto {

    iroha::expected::Result<std::unique_ptr<AddSignatory>, std::string>
    AddSignatory::create(iroha::protocol::Command &command) {
      return shared_model::crypto::Blob::fromHexString(
                 command.add_signatory().public_key())
          | [&command](auto &&pubkey) {
              return std::make_unique<AddSignatory>(
                  command, PubkeyType{std::move(pubkey)});
            };
    }

    AddSignatory::AddSignatory(iroha::protocol::Command &command,
                               PubkeyType pubkey)
        : add_signatory_{command.add_signatory()}, pubkey_(std::move(pubkey)) {}

    const interface::types::AccountIdType &AddSignatory::accountId() const {
      return add_signatory_.account_id();
    }

    const PubkeyType &AddSignatory::pubkey() const {
      return pubkey_;
    }

  }  // namespace proto
}  // namespace shared_model
