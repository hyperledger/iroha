/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_CREATE_ACCOUNT_HPP
#define IROHA_PROTO_CREATE_ACCOUNT_HPP

#include "interfaces/commands/create_account.hpp"

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "cryptography/public_key.hpp"

namespace shared_model {
  namespace proto {

    class CreateAccount final : public CopyableProto<interface::CreateAccount,
                                                     iroha::protocol::Command,
                                                     CreateAccount> {
     public:
      template <typename CommandType>
      explicit CreateAccount(CommandType &&command);

      CreateAccount(const CreateAccount &o);

      CreateAccount(CreateAccount &&o) noexcept;

      const interface::types::PubkeyType &pubkey() const override;

      const interface::types::AccountNameType &accountName() const override;

      const interface::types::DomainIdType &domainId() const override;

     private:
      const iroha::protocol::CreateAccount &create_account_;

      const interface::types::PubkeyType pubkey_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_CREATE_ACCOUNT_HPP
