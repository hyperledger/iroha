/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/commands/revoke_permission.hpp"

namespace shared_model {
  namespace interface {

    bool RevokePermission::operator==(const ModelType &rhs) const {
      return accountId() == rhs.accountId()
          and permissionName() == rhs.permissionName();
    }

  }  // namespace interface
}  // namespace shared_model
