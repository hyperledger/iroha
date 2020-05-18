/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_CREATE_ACCOUNT_HPP
#define IROHA_PROTO_CREATE_ACCOUNT_HPP

#include "interfaces/commands/create_account.hpp"

#include "commands.pb.h"

namespace shared_model {
  namespace proto {

    class CreateAccount final : public interface::CreateAccount {
     public:
      explicit CreateAccount(iroha::protocol::Command &command);

      const std::string &pubkey() const override;

      const interface::types::AccountNameType &accountName() const override;

      const interface::types::DomainIdType &domainId() const override;

     private:
      const iroha::protocol::CreateAccount &create_account_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_CREATE_ACCOUNT_HPP
