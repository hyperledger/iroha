/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef PERMISSION_TO_STRING_HPP
#define PERMISSION_TO_STRING_HPP

#include <string>
#include <vector>

#include "interfaces/permissions.hpp"

namespace shared_model {
  namespace interface {
    class PermissionToString {
     public:
      virtual ~PermissionToString() = default;
      /**
       * @param sm object for conversion
       * @return its string representation
       */
      virtual std::string toString(permissions::Role r) const = 0;

      /**
       * @param sm object for conversion
       * @return its string representation
       */
      virtual std::string toString(permissions::Grantable r) const = 0;

      /**
       * @param set for stringify
       * @return vector of string representation of set elements
       */
      std::vector<std::string> setToString(const RolePermissionSet &set) const;

      /**
       * @param set for stringify
       * @return vector of string representation of set elements
       */
      std::vector<std::string> setToString(
          const GrantablePermissionSet &set) const;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // PERMISSION_TO_STRING_HPP
