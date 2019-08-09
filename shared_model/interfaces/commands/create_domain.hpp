/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_CREATE_DOMAIN_HPP
#define IROHA_SHARED_MODEL_CREATE_DOMAIN_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Create domain in Iroha
     */
    class CreateDomain : public ModelPrimitive<CreateDomain> {
     public:
      /**
       * @return Id of the domain to create
       */
      virtual const types::DomainIdType &domainId() const = 0;
      /**
       * @return default role of the user in the domain
       */
      virtual const types::RoleIdType &userDefaultRole() const = 0;

      std::string toString() const override;

      bool operator==(const ModelType &rhs) const override;
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_CREATE_DOMAIN_HPP
