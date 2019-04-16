/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_ADD_SIGNATORY_HPP
#define IROHA_PROTO_ADD_SIGNATORY_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "cryptography/public_key.hpp"
#include "interfaces/commands/add_signatory.hpp"

namespace shared_model {
  namespace proto {
    class AddSignatory final : public CopyableProto<interface::AddSignatory,
                                                    iroha::protocol::Command,
                                                    AddSignatory> {
     public:
      template <typename CommandType>
      explicit AddSignatory(CommandType &&command);

      AddSignatory(const AddSignatory &o);

      AddSignatory(AddSignatory &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::PubkeyType &pubkey() const override;

     private:
      const iroha::protocol::AddSignatory &add_signatory_;

      const interface::types::PubkeyType pubkey_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_ADD_SIGNATORY_HPP
