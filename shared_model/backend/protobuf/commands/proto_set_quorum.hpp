/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_SET_QUORUM_HPP
#define IROHA_PROTO_SET_QUORUM_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/set_quorum.hpp"

namespace shared_model {
  namespace proto {
    class SetQuorum final : public CopyableProto<interface::SetQuorum,
                                                 iroha::protocol::Command,
                                                 SetQuorum> {
     public:
      template <typename CommandType>
      explicit SetQuorum(CommandType &&command);

      SetQuorum(const SetQuorum &o);

      SetQuorum(SetQuorum &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      interface::types::QuorumType newQuorum() const override;

     private:
      const iroha::protocol::SetAccountQuorum &set_account_quorum_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_SET_QUORUM_HPP
