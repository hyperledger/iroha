/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ROLE_PERMISSIONS_RESPONSE_HPP
#define IROHA_SHARED_MODEL_ROLE_PERMISSIONS_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Response with all permissions related to role
     */
    class RolePermissionsResponse
        : public ModelPrimitive<RolePermissionsResponse> {
     public:
      /**
       * @return role permissions
       */
      virtual const RolePermissionSet &rolePermissions() const = 0;

      /**
       * Stringify the data.
       * @return string representation of data.
       */
      std::string toString() const override = 0;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ROLE_PERMISSIONS_RESPONSE_HPP
