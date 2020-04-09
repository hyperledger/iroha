/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_REMOVE_SIGNATORY_HPP
#define IROHA_PROTO_REMOVE_SIGNATORY_HPP

#include "interfaces/commands/remove_signatory.hpp"

#include "commands.pb.h"

namespace shared_model {
  namespace proto {

    class RemoveSignatory final : public interface::RemoveSignatory {
     public:
      explicit RemoveSignatory(iroha::protocol::Command &command);

      const interface::types::AccountIdType &accountId() const override;

      const std::string &pubkey() const override;

     private:
      const iroha::protocol::RemoveSignatory &remove_signatory_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_REMOVE_SIGNATORY_HPP
