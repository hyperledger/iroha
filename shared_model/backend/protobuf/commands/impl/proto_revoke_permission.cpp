/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_revoke_permission.hpp"

#include "backend/protobuf/permissions.hpp"

namespace shared_model {
  namespace proto {

    RevokePermission::RevokePermission(iroha::protocol::Command &command)
        : revoke_permission_{command.revoke_permission()} {}

    const interface::types::AccountIdType &RevokePermission::accountId() const {
      return revoke_permission_.account_id();
    }

    interface::permissions::Grantable RevokePermission::permissionName() const {
      return permissions::fromTransport(revoke_permission_.permission());
    }

    std::string RevokePermission::toString() const {
      return detail::PrettyStringBuilder()
          .init("RevokePermission")
          .appendNamed("account_id", accountId())
          .appendNamed("permission", permissions::toString(permissionName()))
          .finalize();
    }

  }  // namespace proto
}  // namespace shared_model
