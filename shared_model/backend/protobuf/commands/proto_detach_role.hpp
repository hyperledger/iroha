/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_DETACH_ROLE_HPP
#define IROHA_PROTO_DETACH_ROLE_HPP

#include "interfaces/commands/detach_role.hpp"

#include "commands.pb.h"

namespace shared_model {
  namespace proto {

    class DetachRole final : public interface::DetachRole {
     public:
      explicit DetachRole(iroha::protocol::Command &command);

      const interface::types::AccountIdType &accountId() const override;

      const interface::types::RoleIdType &roleName() const override;

     private:
      const iroha::protocol::DetachRole &detach_role_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_DETACH_ROLE_HPP
