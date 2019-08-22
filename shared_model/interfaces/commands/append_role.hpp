/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_APPEND_ROLE_HPP
#define IROHA_SHARED_MODEL_APPEND_ROLE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Add role to account used in Iroha
     */
    class AppendRole : public ModelPrimitive<AppendRole> {
     public:
      /**
       * @return Account to add the role
       */
      virtual const types::AccountIdType &accountId() const = 0;
      /**
       * @return Role name to add to account
       */
      virtual const types::RoleIdType &roleName() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_APPEND_ROLE_HPP
