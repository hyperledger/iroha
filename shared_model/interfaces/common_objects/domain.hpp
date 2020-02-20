/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_DOMAIN_HPP
#define IROHA_SHARED_MODEL_DOMAIN_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"
#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Domain object represents administrative unit within the system
     */
    class Domain : public ModelPrimitive<Domain> {
     public:
      /**
       * @return Identity of domain
       */
      virtual const types::DomainIdType &domainId() const = 0;

      /**
       * @return Default role of domain
       */
      virtual const types::RoleIdType &defaultRole() const = 0;
      /**
       * Stringify the data.
       * @return the content of asset.
       */
      std::string toString() const override {
        return detail::PrettyStringBuilder()
            .init("Domain")
            .appendNamed("domainId", domainId())
            .appendNamed("defaultRole", defaultRole())
            .finalize();
      }

      /**
       * Checks equality of objects inside
       * @param rhs - other wrapped value
       * @return true, if wrapped objects are same
       */
      bool operator==(const ModelType &rhs) const override {
        return domainId() == rhs.domainId()
            and defaultRole() == rhs.defaultRole();
      }
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_DOMAIN_HPP
