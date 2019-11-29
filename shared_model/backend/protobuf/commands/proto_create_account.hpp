/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_CREATE_ACCOUNT_HPP
#define IROHA_PROTO_CREATE_ACCOUNT_HPP

#include "interfaces/commands/create_account.hpp"

#include "common/result_fwd.hpp"
#include "cryptography/public_key.hpp"

namespace iroha {
  namespace protocol {
    class CreateAccount;
    class Command;
  }  // namespace protocol
}  // namespace iroha

namespace shared_model {
  namespace proto {

    class CreateAccount final : public interface::CreateAccount {
     public:
      static iroha::expected::Result<std::unique_ptr<CreateAccount>,
                                     std::string>
      create(iroha::protocol::Command &command);

      CreateAccount(iroha::protocol::Command &command,
                    shared_model::interface::types::PubkeyType pubkey);

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
