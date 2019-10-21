/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_PROTO_PERMISSIONS_HPP
#define IROHA_SHARED_MODEL_PROTO_PERMISSIONS_HPP

#include "interfaces/permissions.hpp"

#include <string>
#include <vector>

#include "primitive.pb.h"

namespace shared_model {
  namespace proto {
    namespace permissions {
      /**
       * Perform deserialization without checks
       * @param perm protocol object for conversion
       * @return sm object
       */
      interface::permissions::Role fromTransport(
          iroha::protocol::RolePermission perm) noexcept;

      /**
       * @param sm object for conversion
       * @return protobuf object
       */
      iroha::protocol::RolePermission toTransport(
          interface::permissions::Role r);

      /**
       * @param sm object for conversion
       * @return its string representation
       */
      std::string toString(interface::permissions::Role r);

      /**
       * Perform deserialization without checks
       * @param perm protocol object for conversion
       * @return sm object
       */
      interface::permissions::Grantable fromTransport(
          iroha::protocol::GrantablePermission perm) noexcept;

      /**
       * @param sm object for conversion
       * @return protobuf object
       */
      iroha::protocol::GrantablePermission toTransport(
          interface::permissions::Grantable r);

      /**
       * @param sm object for conversion
       * @return its string representation
       */
      std::string toString(interface::permissions::Grantable r);

      /**
       * @param set for stringify
       * @return vector of string representation of set elements
       */
      std::vector<std::string> toString(
          const interface::PermissionSet<interface::permissions::Role> &set);

      /**
       * @param set for stringify
       * @return vector of string representation of set elements
       */
      std::vector<std::string> toString(
          const interface::PermissionSet<interface::permissions::Grantable>
              &set);
    }  // namespace permissions
  }    // namespace proto
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_PROTO_PERMISSIONS_HPP
