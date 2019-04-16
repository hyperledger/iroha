/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_BIND_HPP
#define IROHA_COMMON_BIND_HPP

#include <ciso646>
#include <type_traits>
#include <utility>

namespace iroha {

  /**
   * Bind operator. If argument has value, dereferences argument and calls
   * given function, which should return wrapped value
   * operator| is used since it has to be binary and left-associative
   * Non-void returning specialization
   *
   * boost::optional<int> f();
   * boost::optional<double> g(int);
   *
   * boost::optional<double> d = f()
   *    | g;
   *
   * std::forward should be used in any reference of arguments because
   * operator bool, operator*, and operator() of arguments can have
   * different implementation with ref-qualifiers
   *
   * Trailing return type checks that result of applying function to
   * unwrapped value results in non-void type
   *
   * @tparam T - monadic type
   * @tparam Transform - transform function type
   * @param t - monadic value
   * @param f - function, which takes dereferenced value, and returns
   * wrapped value
   * @return monadic value, which can be of another type
   */
  template <typename T, typename Transform>
  auto operator|(T &&t, Transform &&f) -> std::enable_if_t<
      not std::is_same<
          decltype(std::forward<Transform>(f)(*std::forward<T>(t))),
          void>::value,
      decltype(std::forward<Transform>(f)(*std::forward<T>(t)))> {
    if (std::forward<T>(t)) {
      return std::forward<Transform>(f)(*std::forward<T>(t));
    }
    return {};
  }

  /**
   * Bind operator. If argument has value, dereferences argument and calls
   * given function, which should return wrapped value
   * operator| is used since it has to be binary and left-associative
   * Void specialization
   *
   * boost::optional<int> f();
   * void g(int);
   *
   * f() | g;
   *
   * std::forward should be used in any reference of arguments because
   * operator bool, operator*, and operator() of arguments can have
   * different implementation with ref-qualifiers
   *
   * Trailing return type checks that result of applying function to
   * unwrapped value results in void type
   *
   * @tparam T - monadic type
   * @tparam Transform - transform function type
   * @param t - monadic value
   * @param f - function, which takes dereferenced value, and returns
   * wrapped value
   */
  template <typename T, typename Transform>
  auto operator|(T &&t, Transform &&f) -> std::enable_if_t<
      std::is_same<decltype(std::forward<Transform>(f)(*std::forward<T>(t))),
                   void>::value> {
    if (std::forward<T>(t)) {
      std::forward<Transform>(f)(*std::forward<T>(t));
    }
  }
}  // namespace iroha

#endif  // IROHA_COMMON_BIND_HPP
