/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_REFERENCE_HOLDER_HPP
#define IROHA_REFERENCE_HOLDER_HPP

#include <boost/variant.hpp>

namespace shared_model {
  namespace detail {
    /**
     * Container designed to store reference or value depending on called ctor
     * @tparam T type of stored value
     */
    template <typename T>
    class ReferenceHolder {
     private:
      using VariantType = boost::variant<T, T &>;

     public:
      template <typename V>
      explicit ReferenceHolder(V &&value) : variant_(std::forward<V>(value)) {}

      using ReferenceType = typename std::add_lvalue_reference_t<T>;
      using PointerType = typename std::add_pointer_t<T>;

      using ConstReferenceType = typename std::add_lvalue_reference_t<const T>;
      using ConstPointerType = typename std::add_pointer_t<const T>;

      ReferenceType operator*() {
        return *ptr();
      }

      PointerType operator->() {
        return ptr();
      }

      PointerType ptr() {
        return &boost::apply_visitor(
            [](auto &value) -> decltype(auto) { return (value); }, variant_);
      }

      ConstReferenceType operator*() const {
        return *ptr();
      }

      ConstPointerType operator->() const {
        return ptr();
      }

      ConstPointerType ptr() const {
        return &boost::apply_visitor(
            [](const auto &value) -> decltype(auto) { return (value); },
            variant_);
      }

     private:
      VariantType variant_;
    };
  }  // namespace detail
}  // namespace shared_model

#endif  // IROHA_REFERENCE_HOLDER_HPP
