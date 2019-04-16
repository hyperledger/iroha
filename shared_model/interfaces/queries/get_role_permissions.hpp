/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_GET_ROLE_PERMISSIONS_HPP
#define IROHA_SHARED_MODEL_GET_ROLE_PERMISSIONS_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Get all permissions related to specific role
     */
    class GetRolePermissions : public ModelPrimitive<GetRolePermissions> {
     public:
      /**
       * @return role identifier containing requested permissions
       */
      virtual const types::RoleIdType &roleId() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_GET_ROLES_HPP
