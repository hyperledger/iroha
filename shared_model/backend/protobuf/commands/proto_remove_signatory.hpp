/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_REMOVE_SIGNATORY_HPP
#define IROHA_PROTO_REMOVE_SIGNATORY_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "cryptography/public_key.hpp"
#include "interfaces/commands/remove_signatory.hpp"

namespace shared_model {
  namespace proto {

    class RemoveSignatory final
        : public CopyableProto<interface::RemoveSignatory,
                               iroha::protocol::Command,
                               RemoveSignatory> {
     public:
      template <typename CommandType>
      explicit RemoveSignatory(CommandType &&command);

      RemoveSignatory(const RemoveSignatory &o);

      RemoveSignatory(RemoveSignatory &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::PubkeyType &pubkey() const override;

     private:
      const iroha::protocol::RemoveSignatory &remove_signatory_;

      const interface::types::PubkeyType pubkey_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_REMOVE_SIGNATORY_HPP
