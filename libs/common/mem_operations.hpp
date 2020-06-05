/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_MEM_OPERATIONS_HPP
#define IROHA_COMMON_MEM_OPERATIONS_HPP

#include <cstring>

namespace iroha {

  template <typename T>
  void memzero(T &t) {
    static_assert(std::is_pod<T>::value, "T must be POD.");
    std::memset(&t, 0, sizeof(t));
  }

  template <typename T>
  void memcpy(T &dst, T const &src) {
    static_assert(std::is_pod<T>::value, "T must be POD.");
    std::memcpy(&dst, &src, sizeof(src));
  }
}  // namespace iroha

#endif  // IROHA_COMMON_MEM_OPERATIONS_HPP
