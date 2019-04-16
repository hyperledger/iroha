/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "backend/protobuf/commands/proto_append_role.hpp"

namespace shared_model {
  namespace proto {

    template <typename CommandType>
    AppendRole::AppendRole(CommandType &&command)
        : CopyableProto(std::forward<CommandType>(command)),
          append_role_{proto_->append_role()} {}

    template AppendRole::AppendRole(AppendRole::TransportType &);
    template AppendRole::AppendRole(const AppendRole::TransportType &);
    template AppendRole::AppendRole(AppendRole::TransportType &&);

    AppendRole::AppendRole(const AppendRole &o) : AppendRole(o.proto_) {}

    AppendRole::AppendRole(AppendRole &&o) noexcept
        : AppendRole(std::move(o.proto_)) {}

    const interface::types::AccountIdType &AppendRole::accountId() const {
      return append_role_.account_id();
    }

    const interface::types::RoleIdType &AppendRole::roleName() const {
      return append_role_.role_name();
    }

  }  // namespace proto
}  // namespace shared_model
