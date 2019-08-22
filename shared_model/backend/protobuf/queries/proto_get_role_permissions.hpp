/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ROLE_PERMISSIONS_H
#define IROHA_PROTO_GET_ROLE_PERMISSIONS_H

#include "backend/protobuf/common_objects/trivial_proto.hpp"
#include "interfaces/queries/get_role_permissions.hpp"
#include "queries.pb.h"

namespace shared_model {
  namespace proto {
    class GetRolePermissions final
        : public TrivialProto<interface::GetRolePermissions,
                              iroha::protocol::Query> {
     public:
      template <typename QueryType>
      explicit GetRolePermissions(QueryType &&query);

      GetRolePermissions(const GetRolePermissions &o);

      GetRolePermissions(GetRolePermissions &&o) noexcept;

      const interface::types::RoleIdType &roleId() const override;

     private:
      // ------------------------------| fields |-------------------------------
      const iroha::protocol::GetRolePermissions &role_permissions_;
    };

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ROLE_PERMISSIONS_H
