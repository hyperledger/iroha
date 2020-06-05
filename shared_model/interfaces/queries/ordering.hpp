/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_SHARED_MODEL_ORDERING_HPP
#define IROHA_SHARED_MODEL_ORDERING_HPP

#include "interfaces/base/model_primitive.hpp"
#include "interfaces/common_objects/types.hpp"

namespace shared_model {
  namespace interface {

    /**
     * Class Ordering provides description of data ordering in queries.
     * General note: this is interface.
     */
    class Ordering : public ModelPrimitive<Ordering> {
     public:
      /**
       * Field name for ordering entry.
       */
      enum struct Field : size_t {
        kCreatedTime = 0,
        kPosition,
        //--------------
        kMaxValueCount,
        kUnknownValue = kMaxValueCount
      };

      /**
       * Ordering direction for each field.
       */
      enum struct Direction : size_t {
        kAscending = 0,
        kDescending,
        //--------------
        kMaxValueCount,
        kUnknownValue = kMaxValueCount
      };

      /**
       * Ordering entry - the description of the ordering for the field.
       */
      struct OrderingEntry {
        Field field;
        Direction direction;
      };

      /**
       * Append - stores field and direction entry uniquely. The
       * insertion order determines the ordering priority.
       * @return the insertion result(true - inserted, false - skipped).
       */
      virtual bool append(Field field, Direction direction) = 0;

      /**
       * Reset - drops all saved data.
       */
      virtual void reset() = 0;

      /**
       * Get - returns data sorted in the insertion order.
       * @orderingEntry is a reference to a const OrderingEntry pointer, which
       * positions to the first element
       * @count is a number of OrderingEntry items
       */
      virtual void get(OrderingEntry const *&orderingEntry,
                       size_t &count) const = 0;

      std::string toString() const override;
      bool operator==(const ModelType &rhs) const override;
    };

  }  // namespace interface
}  // namespace shared_model

#endif  // IROHA_SHARED_MODEL_ORDERING_HPP
