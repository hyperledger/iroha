/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_AMOUNT_HPP
#define IROHA_SHARED_MODEL_AMOUNT_HPP

#include "interfaces/base/model_primitive.hpp"

#include <string_view>

#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Representation of fixed point number
     */
    class Amount final : public ModelPrimitive<Amount> {
     public:
      explicit Amount(std::string_view amount);

      explicit Amount(types::PrecisionType precision);

      Amount(Amount const &other);

      Amount(Amount &&other) noexcept;

      Amount &operator=(Amount const &other);

      Amount &operator=(Amount &&other) noexcept;

      ~Amount() override;

      /**
       * Returns a value less than zero if Amount is negative, a value greater
       * than zero if Amount is positive, and zero if Amount is zero.
       */
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
      std::string const &toStringRepr() const;

      Amount &operator+=(Amount const &other);

      Amount &operator-=(Amount const &other);

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
      std::unique_ptr<Impl> impl_;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_SHARED_MODEL_AMOUNT_HPP
