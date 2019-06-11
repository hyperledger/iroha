/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_detach_role.hpp"

namespace shared_model {
  namespace proto {

    DetachRole::DetachRole(iroha::protocol::Command &command)
        : detach_role_{command.detach_role()} {}

    const interface::types::AccountIdType &DetachRole::accountId() const {
      return detach_role_.account_id();
    }

    const interface::types::RoleIdType &DetachRole::roleName() const {
      return detach_role_.role_name();
    }

  }  // namespace proto
}  // namespace shared_model
