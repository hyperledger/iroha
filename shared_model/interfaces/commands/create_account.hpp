/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_CREATE_ACCOUNT_HPP
#define IROHA_SHARED_MODEL_CREATE_ACCOUNT_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Create acccount in Iroha domain
     */
    class CreateAccount : public ModelPrimitive<CreateAccount> {
     public:
      /**
       * @return Name of the account to create in Iroha
       */
      virtual const types::AccountNameType &accountName() const = 0;
      /**
       * @return Iroha domain in which account will be created
       */
      virtual const types::DomainIdType &domainId() const = 0;
      /**
       * @return Initial account public key
       */
      virtual const std::string &pubkey() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_CREATE_ACCOUNT_HPP
