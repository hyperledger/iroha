/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/query_responses/proto_role_permissions_response.hpp"

#include <boost/range/numeric.hpp>
#include "backend/protobuf/permissions.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace proto {

    template <typename QueryResponseType>
    RolePermissionsResponse::RolePermissionsResponse(
        QueryResponseType &&queryResponse)
        : CopyableProto(std::forward<QueryResponseType>(queryResponse)),
          role_permissions_response_{proto_->role_permissions_response()},
          role_permissions_{boost::accumulate(
              role_permissions_response_.permissions(),
              interface::RolePermissionSet{},
              [](auto &&permissions, const auto &permission) {
                permissions.set(permissions::fromTransport(
                    static_cast<iroha::protocol::RolePermission>(permission)));
                return std::forward<decltype(permissions)>(permissions);
              })} {}

    template RolePermissionsResponse::RolePermissionsResponse(
        RolePermissionsResponse::TransportType &);
    template RolePermissionsResponse::RolePermissionsResponse(
        const RolePermissionsResponse::TransportType &);
    template RolePermissionsResponse::RolePermissionsResponse(
        RolePermissionsResponse::TransportType &&);

    RolePermissionsResponse::RolePermissionsResponse(
        const RolePermissionsResponse &o)
        : RolePermissionsResponse(o.proto_) {}

    RolePermissionsResponse::RolePermissionsResponse(
        RolePermissionsResponse &&o)
        : RolePermissionsResponse(std::move(o.proto_)) {}

    const interface::RolePermissionSet &
    RolePermissionsResponse::rolePermissions() const {
      return role_permissions_;
    }

    std::string RolePermissionsResponse::toString() const {
      return detail::PrettyStringBuilder()
          .init("RolePermissionsResponse")
          .appendAll(permissions::toString(rolePermissions()),
                     [](auto p) { return p; })
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
