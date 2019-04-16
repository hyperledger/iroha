/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_APPEND_ROLE_HPP
#define IROHA_PROTO_APPEND_ROLE_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/append_role.hpp"

namespace shared_model {
  namespace proto {

    class AppendRole final : public CopyableProto<interface::AppendRole,
                                                  iroha::protocol::Command,
                                                  AppendRole> {
     public:
      template <typename CommandType>
      explicit AppendRole(CommandType &&command);

      AppendRole(const AppendRole &o);

      AppendRole(AppendRole &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::RoleIdType &roleName() const override;

     private:
      const iroha::protocol::AppendRole &append_role_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_APPEND_ROLE_HPP
