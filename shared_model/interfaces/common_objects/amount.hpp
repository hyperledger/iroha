/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_AMOUNT_HPP
#define IROHA_SHARED_MODEL_AMOUNT_HPP

#include "interfaces/base/model_primitive.hpp"

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Representation of fixed point number
     */
    class Amount final : public ModelPrimitive<Amount> {
     public:
      explicit Amount(const std::string &amount);

      int sign() const;

      /**
       * Gets the position of precision
       * @return the position of precision
       */
      types::PrecisionType precision() const;

      /**
       * String representation.
       * @return string representation of the asset.
       */
      std::string toStringRepr() const;

      /**
       * Checks equality of objects inside
       * @param rhs - other wrapped value
       * @return true, if wrapped objects are same
       */
      bool operator==(const ModelType &rhs) const override;

      /**
       * Stringify the data.
       * @return the content of asset.
       */
      std::string toString() const override;

     private:
      struct Impl;

      const std::shared_ptr<const Impl> impl_;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_AMOUNT_HPP
