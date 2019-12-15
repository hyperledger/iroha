/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/detach_role.hpp"

namespace shared_model {
  namespace interface {

    std::string DetachRole::toString() const {
      return detail::PrettyStringBuilder()
          .init("DetachRole")
          .appendNamed("role_name", roleName())
          .appendNamed("account_id", accountId())
          .finalize();
    }

    bool DetachRole::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId() and roleName() == rhs.roleName();
    }

  }  // namespace interface
}  // namespace shared_model
