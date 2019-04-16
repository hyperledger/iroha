/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_IS_ANY_HPP
#define IROHA_IS_ANY_HPP

#include <type_traits>

namespace iroha {

  template <typename T, typename... Rest>
  struct is_any : std::false_type {};

  template <typename T, typename First>
  struct is_any<T, First> : std::is_same<T, First> {};

  /**
   * Disjunctive type check. Returns true if first type is contained in provided
   * list, false otherwise
   * @tparam T first type
   * @tparam First head of types list
   * @tparam Rest tail of types list
   */
  template <typename T, typename First, typename... Rest>
  struct is_any<T, First, Rest...>
      : std::integral_constant<bool,
                               std::is_same<T, First>::value
                                   || is_any<T, Rest...>::value> {};

}  // namespace iroha

#endif  // IROHA_IS_ANY_HPP
