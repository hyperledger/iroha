/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

namespace stack_overflow {

  namespace detail {
    template <class T, class U>
    using forwarded_type =
        std::conditional_t<std::is_lvalue_reference<T>::value,
                           std::remove_reference_t<U> &,
                           std::remove_reference_t<U> &&>;
  }

  /**
   * Foward a value like the reference one.
   *
   * https://stackoverflow.com/a/29780197/1946763
   * If T is rvalue reference, u will be passed by U&&, otherwise by U&.
   *
   * @tparam T - the type determining how to forward
   * @tparam U - the type forwarded like T
   * @param u - the value to be forwarded
   */
  template <class T, class U>
  detail::forwarded_type<T, U> forward_like(U &&u) {
    return std::forward<detail::forwarded_type<T, U>>(std::forward<U>(u));
  }

}  // namespace stack_overflow
