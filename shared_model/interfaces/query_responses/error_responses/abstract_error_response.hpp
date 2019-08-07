/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_ABSTRACT_ERROR_RESPONSE_HPP
#define IROHA_ABSTRACT_ERROR_RESPONSE_HPP

#include "interfaces/base/model_primitive.hpp"

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Abstract error response
     * @tparam Model - concrete model error response
     */
    template <typename Model>
    class AbstractErrorResponse : public ModelPrimitive<Model> {
     private:
      /**
       * @return string representation of error reason
       */
      virtual std::string reason() const = 0;

     public:
      // ------------------------| Primitive override |-------------------------

      std::string toString() const override {
        return detail::PrettyStringBuilder().init(reason()).finalize();
      }

      bool operator==(const Model &rhs) const override {
        return true;
      }
    };
  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_ABSTRACT_ERROR_RESPONSE_HPP
