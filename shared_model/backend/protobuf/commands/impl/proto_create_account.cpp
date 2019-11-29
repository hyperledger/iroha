/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_create_account.hpp"

#include "commands.pb.h"
#include "common/result.hpp"
#include "cryptography/blob.hpp"
#include "cryptography/hash.hpp"

using shared_model::interface::types::PubkeyType;

namespace shared_model {
  namespace proto {

    iroha::expected::Result<std::unique_ptr<CreateAccount>, std::string>
    CreateAccount::create(iroha::protocol::Command &command) {
      return shared_model::crypto::Blob::fromHexString(
                 command.create_account().public_key())
          | [&command](auto &&pubkey) {
              return std::make_unique<CreateAccount>(
                  command, PubkeyType{std::move(pubkey)});
            };
    }

    CreateAccount::CreateAccount(iroha::protocol::Command &command,
                                 PubkeyType pubkey)
        : create_account_{command.create_account()},
          pubkey_(std::move(pubkey)) {}

    const PubkeyType &CreateAccount::pubkey() const {
      return pubkey_;
    }

    const interface::types::AccountNameType &CreateAccount::accountName()
        const {
      return create_account_.account_name();
    }

    const interface::types::DomainIdType &CreateAccount::domainId() const {
      return create_account_.domain_id();
    }

  }  // namespace proto
}  // namespace shared_model
