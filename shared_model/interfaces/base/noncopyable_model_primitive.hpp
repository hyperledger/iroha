/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_NONCOPYABLE_MODEL_PRIMITIVE_HPP
#define IROHA_NONCOPYABLE_MODEL_PRIMITIVE_HPP

#include <ciso646>

#include "utils/string_builder.hpp"

namespace shared_model {
  namespace interface {
    /**
     * Base class of domain objects which are not intended to be copied.
     * @tparam Model - shared model type
     */
    template <typename Model>
    class NonCopyableModelPrimitive {
     public:
      using ModelType = Model;

      NonCopyableModelPrimitive() = default;

      NonCopyableModelPrimitive(const NonCopyableModelPrimitive &) = delete;
      NonCopyableModelPrimitive &operator=(const NonCopyableModelPrimitive &) =
          delete;

      NonCopyableModelPrimitive(NonCopyableModelPrimitive &&) noexcept =
          default;

      /**
       * Make string representation of object for development
       * @return string with internal state of object
       */
      virtual std::string toString() const {
        return detail::PrettyStringBuilder()
            .init("NonCopyablePrimitive")
            .append("address", std::to_string(reinterpret_cast<uint64_t>(this)))
            .finalize();
      }

      virtual bool operator==(const ModelType &rhs) const = 0;

      virtual bool operator!=(const ModelType &rhs) const {
        return not(*this == rhs);
      }

      virtual ~NonCopyableModelPrimitive() = default;
    };
  }  // namespace interface
}  // namespace shared_model
#endif  // IROHA_NONCOPYABLE_MODEL_PRIMITIVE_HPP
