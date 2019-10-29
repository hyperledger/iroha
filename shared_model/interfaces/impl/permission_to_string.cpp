/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "interfaces/permission_to_string.hpp"

using namespace shared_model::interface;

namespace {
  template <typename PermSet>
  std::vector<std::string> permSetToStringVector(
      const PermissionToString &permission_to_string, PermSet s) {
    std::vector<std::string> v;
    s.iterate(
        [&](auto perm) { v.push_back(permission_to_string.toString(perm)); });
    return v;
  }
}  // namespace

std::vector<std::string> PermissionToString::setToString(
    const interface::RolePermissionSet &set) const {
  return permSetToStringVector(*this, set);
}

std::vector<std::string> PermissionToString::setToString(
    const interface::GrantablePermissionSet &set) const {
  return permSetToStringVector(*this, set);
}
