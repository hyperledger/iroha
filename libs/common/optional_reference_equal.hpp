/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_OPTIONAL_REFERENCE_EQUAL_HPP
#define IROHA_OPTIONAL_REFERENCE_EQUAL_HPP

#include <functional>
#include <optional>

namespace iroha {

  /**
   * Compares optional references by accesing the stored reference, if it is
   * present
   */
  template <typename T>
  constexpr bool optionalReferenceEqual(
      const std::optional<std::reference_wrapper<T>> &lhs,
      const std::optional<std::reference_wrapper<T>> &rhs) {
    return static_cast<bool>(lhs) == static_cast<bool>(rhs)
        and (not lhs or lhs->get() == rhs->get());
  }
}  // namespace iroha

#endif  // IROHA_OPTIONAL_REFERENCE_EQUAL_HPP
