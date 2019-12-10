/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_REMOVE_SIGNATORY_HPP
#define IROHA_PROTO_REMOVE_SIGNATORY_HPP

#include "interfaces/commands/remove_signatory.hpp"

#include "commands.pb.h"
#include "common/result.hpp"
#include "cryptography/public_key.hpp"

namespace shared_model {
  namespace proto {

    class RemoveSignatory final : public interface::RemoveSignatory {
     public:
      static iroha::expected::Result<std::unique_ptr<RemoveSignatory>,
                                     std::string>
      create(iroha::protocol::Command &command);

      RemoveSignatory(iroha::protocol::Command &command,
                      shared_model::interface::types::PubkeyType pubkey);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::PubkeyType &pubkey() const override;

     private:
      const iroha::protocol::RemoveSignatory &remove_signatory_;

      const interface::types::PubkeyType pubkey_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_REMOVE_SIGNATORY_HPP
