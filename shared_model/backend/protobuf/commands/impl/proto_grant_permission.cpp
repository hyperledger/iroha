/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_grant_permission.hpp"

#include "backend/protobuf/permissions.hpp"

namespace shared_model {
  namespace proto {

    GrantPermission::GrantPermission(iroha::protocol::Command &command)
        : grant_permission_{command.grant_permission()} {}

    const interface::types::AccountIdType &GrantPermission::accountId() const {
      return grant_permission_.account_id();
    }

    interface::permissions::Grantable GrantPermission::permissionName() const {
      return permissions::fromTransport(grant_permission_.permission());
    }

    std::string GrantPermission::toString() const {
      return detail::PrettyStringBuilder()
          .init("GrantPermission")
          .appendNamed("account_id", accountId())
          .appendNamed("permission", permissions::toString(permissionName()))
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
