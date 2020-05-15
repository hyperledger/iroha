/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_BM_UTILS_HPP
#define IROHA_BM_UTILS_HPP

#include "builders/protobuf/unsigned_proto.hpp"
#include "datetime/time.hpp"
#include "framework/common_constants.hpp"
#include "framework/integration_framework/integration_test_framework.hpp"
#include "module/shared_model/builders/protobuf/test_transaction_builder.hpp"

namespace benchmark {
  namespace utils {
    TestUnsignedTransactionBuilder createUserWithPerms(
        const std::string &user,
        shared_model::interface::types::PublicKeyHexStringView key,
        const std::string &role_id,
        const shared_model::interface::RolePermissionSet &perms) {
      const auto user_id = user + "@" + common_constants::kDomain;
      return TestUnsignedTransactionBuilder()
          .createAccount(user, common_constants::kDomain, key)
          .creatorAccountId(common_constants::kAdminId)
          .createdTime(iroha::time::now())
          .quorum(1)
          .detachRole(user_id, common_constants::kDefaultRole)
          .createRole(role_id, perms)
          .appendRole(user_id, role_id);
    }
  }  // namespace utils
}  // namespace benchmark

#endif  // IROHA_BM_UTILS_HPP
