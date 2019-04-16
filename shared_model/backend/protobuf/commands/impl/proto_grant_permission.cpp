/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_grant_permission.hpp"
#include "backend/protobuf/permissions.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    GrantPermission::GrantPermission(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          grant_permission_{proto_->grant_permission()} {}

    template GrantPermission::GrantPermission(GrantPermission::TransportType &);
    template GrantPermission::GrantPermission(
        const GrantPermission::TransportType &);
    template GrantPermission::GrantPermission(
        GrantPermission::TransportType &&);

    GrantPermission::GrantPermission(const GrantPermission &o)
        : GrantPermission(o.proto_) {}

    GrantPermission::GrantPermission(GrantPermission &&o) noexcept
        : GrantPermission(std::move(o.proto_)) {}

    const interface::types::AccountIdType &GrantPermission::accountId() const {
      return grant_permission_.account_id();
    }

    interface::permissions::Grantable GrantPermission::permissionName() const {
      return permissions::fromTransport(grant_permission_.permission());
    }

    std::string GrantPermission::toString() const {
      return detail::PrettyStringBuilder()
          .init("GrantPermission")
          .append("account_id", accountId())
          .append("permission", permissions::toString(permissionName()))
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
