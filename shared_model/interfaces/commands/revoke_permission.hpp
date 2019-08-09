/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_REVOKE_PERMISSION_HPP
#define IROHA_SHARED_MODEL_REVOKE_PERMISSION_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"
#include "interfaces/permissions.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Revoke permission from account
     */
    class RevokePermission : public ModelPrimitive<RevokePermission> {
     public:
      /**
       * @return account from which revoke permission
       */
      virtual const types::AccountIdType &accountId() const = 0;

      /**
       * @return Permission to revoke
       */
      virtual permissions::Grantable permissionName() const = 0;

      std::string toString() const override = 0;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_REVOKE_PERMISSION_HPP
