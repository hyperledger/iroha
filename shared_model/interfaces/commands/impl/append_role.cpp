/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/append_role.hpp"

namespace shared_model {
  namespace interface {

    std::string AppendRole::toString() const {
      return detail::PrettyStringBuilder()
          .init("AppendRole")
          .appendNamed("role_name", roleName())
          .appendNamed("account_id", accountId())
          .finalize();
    }

    bool AppendRole::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and roleName() == rhs.roleName();
    }

  }  // namespace interface
}  // namespace shared_model
