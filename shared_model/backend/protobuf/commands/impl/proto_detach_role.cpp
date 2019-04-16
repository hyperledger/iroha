/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_detach_role.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    DetachRole::DetachRole(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          detach_role_{proto_->detach_role()} {}

    template DetachRole::DetachRole(DetachRole::TransportType &);
    template DetachRole::DetachRole(const DetachRole::TransportType &);
    template DetachRole::DetachRole(DetachRole::TransportType &&);

    DetachRole::DetachRole(const DetachRole &o) : DetachRole(o.proto_) {}

    DetachRole::DetachRole(DetachRole &&o) noexcept
        : DetachRole(std::move(o.proto_)) {}

    const interface::types::AccountIdType &DetachRole::accountId() const {
      return detach_role_.account_id();
    }

    const interface::types::RoleIdType &DetachRole::roleName() const {
      return detach_role_.role_name();
    }

  }  // namespace proto
}  // namespace shared_model
