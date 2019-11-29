/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_PROTO_GET_ROLES_H
#define IROHA_PROTO_GET_ROLES_H

#include "interfaces/queries/get_roles.hpp"

namespace shared_model {
  namespace proto {
    class GetRoles final : public interface::GetRoles {};

  }  // namespace proto
}  // namespace shared_model

#endif  // IROHA_PROTO_GET_ROLES_H
