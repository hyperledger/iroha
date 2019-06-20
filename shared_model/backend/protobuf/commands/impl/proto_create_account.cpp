/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_create_account.hpp"

#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    CreateAccount::CreateAccount(iroha::protocol::Command &command)
        : create_account_{command.create_account()},
          pubkey_{crypto::Hash::fromHexString(create_account_.public_key())} {}

    const interface::types::PubkeyType &CreateAccount::pubkey() const {
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
