/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_CREATE_ROLE_HPP
#define IROHA_SHARED_MODEL_CREATE_ROLE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Create new role in Iroha
     */
    class CreateRole : public ModelPrimitive<CreateRole> {
     public:
      /**
       * @return Id of the domain to create
       */
      virtual const types::RoleIdType &roleName() const = 0;

      /**
       * @return permissions associated with the role
       */
      virtual const RolePermissionSet &rolePermissions() const = 0;

      std::string toString() const override = 0;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_CREATE_ROLE_HPP
