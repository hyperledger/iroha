/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_APPEND_ROLE_HPP
#define IROHA_PROTO_APPEND_ROLE_HPP

#include "interfaces/commands/append_role.hpp"

#include "commands.pb.h"

namespace shared_model {
  namespace proto {

    class AppendRole final : public interface::AppendRole {
     public:
      explicit AppendRole(iroha::protocol::Command &command);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::RoleIdType &roleName() const override;

     private:
      const iroha::protocol::AppendRole &append_role_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_APPEND_ROLE_HPP
