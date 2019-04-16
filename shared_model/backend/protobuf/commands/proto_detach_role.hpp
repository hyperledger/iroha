/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_DETACH_ROLE_HPP
#define IROHA_PROTO_DETACH_ROLE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/detach_role.hpp"

namespace shared_model {
  namespace proto {

    class DetachRole final : public CopyableProto<interface::DetachRole,
                                                  iroha::protocol::Command,
                                                  DetachRole> {
     public:
      template <typename CommandType>
      explicit DetachRole(CommandType &&command);

      DetachRole(const DetachRole &o);

      DetachRole(DetachRole &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::RoleIdType &roleName() const override;

     private:
      const iroha::protocol::DetachRole &detach_role_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_DETACH_ROLE_HPP
