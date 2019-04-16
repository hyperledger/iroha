/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GRANT_PERMISSION_HPP
#define IROHA_PROTO_GRANT_PERMISSION_HPP

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "commands.pb.h"
#include "interfaces/commands/grant_permission.hpp"

namespace shared_model {
  namespace proto {

    class GrantPermission final
        : public CopyableProto<interface::GrantPermission,
                               iroha::protocol::Command,
                               GrantPermission> {
     public:
      template <typename CommandType>
      explicit GrantPermission(CommandType &&command);

      GrantPermission(const GrantPermission &o);

      GrantPermission(GrantPermission &&o) noexcept;

      const interface::types::AccountIdType &accountId() const override;

      interface::permissions::Grantable permissionName() const override;

      std::string toString() const override;

     private:
      const iroha::protocol::GrantPermission &grant_permission_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GRANT_PERMISSION_HPP
