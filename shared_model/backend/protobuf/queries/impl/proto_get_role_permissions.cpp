/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/queries/proto_get_role_permissions.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryType>
    GetRolePermissions::GetRolePermissions(QueryType &&query)
        : TrivialProto(std::forward<QueryType>(query)),
          role_permissions_{proto_->payload().get_role_permissions()} {}

    template GetRolePermissions::GetRolePermissions(
        GetRolePermissions::TransportType &);
    template GetRolePermissions::GetRolePermissions(
        const GetRolePermissions::TransportType &);
    template GetRolePermissions::GetRolePermissions(
        GetRolePermissions::TransportType &&);

    GetRolePermissions::GetRolePermissions(const GetRolePermissions &o)
        : GetRolePermissions(o.proto_) {}

    GetRolePermissions::GetRolePermissions(GetRolePermissions &&o) noexcept
        : GetRolePermissions(std::move(o.proto_)) {}

    const interface::types::RoleIdType &GetRolePermissions::roleId() const {
      return role_permissions_.role_id();
    }

  }  // namespace proto
}  // namespace shared_model
