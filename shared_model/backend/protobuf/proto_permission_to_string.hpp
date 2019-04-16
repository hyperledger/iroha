/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PROTO_PERMISSION_TO_STRING_HPP
#define PROTO_PERMISSION_TO_STRING_HPP

#include "interfaces/permission_to_string.hpp"

namespace shared_model {
  namespace proto {
    class ProtoPermissionToString : public interface::PermissionToString {
     public:
      std::string toString(interface::permissions::Role r) override;
      std::string toString(interface::permissions::Grantable r) override;

      std::vector<std::string> toString(
          const interface::RolePermissionSet &set) override;
      std::vector<std::string> toString(
          const interface::GrantablePermissionSet &set) override;
    };
  }  // namespace proto
}  // namespace shared_model

#endif  // PROTO_PERMISSION_TO_STRING_HPP
