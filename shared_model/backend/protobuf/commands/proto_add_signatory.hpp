/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ADD_SIGNATORY_HPP
#define IROHA_PROTO_ADD_SIGNATORY_HPP

#include "interfaces/commands/add_signatory.hpp"

#include "commands.pb.h"
#include "common/result.hpp"
#include "cryptography/public_key.hpp"

namespace shared_model {
  namespace proto {
    class AddSignatory final : public interface::AddSignatory {
     public:
      static iroha::expected::Result<std::unique_ptr<AddSignatory>, std::string>
      create(iroha::protocol::Command &command);

      AddSignatory(iroha::protocol::Command &command,
                   shared_model::interface::types::PubkeyType pubkey);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::PubkeyType &pubkey() const override;

     private:
      const iroha::protocol::AddSignatory &add_signatory_;

      const interface::types::PubkeyType pubkey_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ADD_SIGNATORY_HPP
