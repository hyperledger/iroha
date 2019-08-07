/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ACCOUNT_RESPONSE_HPP
#define IROHA_SHARED_MODEL_ACCOUNT_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/account.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Provide response with account
     */
    class AccountResponse : public ModelPrimitive<AccountResponse> {
     public:
      /// Collection of role_id types
      using AccountRolesIdType = std::vector<types::RoleIdType>;

      /**
       * @return the fetched account.
       */
      virtual const Account &account() const = 0;

      /**
       * @return roles attached to the account
       */
      virtual const AccountRolesIdType &roles() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_ACCOUNT_RESPONSE_HPP
