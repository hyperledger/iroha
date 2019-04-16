/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_create_account.hpp"
#include "cryptography/hash.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    CreateAccount::CreateAccount(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          create_account_{proto_->create_account()},
          pubkey_{crypto::Hash::fromHexString(create_account_.public_key())} {}

    template CreateAccount::CreateAccount(CreateAccount::TransportType &);
    template CreateAccount::CreateAccount(const CreateAccount::TransportType &);
    template CreateAccount::CreateAccount(CreateAccount::TransportType &&);

    CreateAccount::CreateAccount(const CreateAccount &o)
        : CreateAccount(o.proto_) {}

    CreateAccount::CreateAccount(CreateAccount &&o) noexcept
        : CreateAccount(std::move(o.proto_)) {}

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
