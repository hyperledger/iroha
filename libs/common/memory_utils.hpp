/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_MEMORY_UTILS_HPP
#define IROHA_MEMORY_UTILS_HPP

#include <type_traits>
#include <cstring>

namespace iroha { namespace memory {

  template<typename T> void memzero(T& t) {
    static_assert(std::is_pod<T>::value, "To zero memory T must be POD!");
    memset(&t, 0, sizeof(t));
  }

  template<typename T> void memcpy(T& dst, T const &src) {
    static_assert(std::is_pod<T>::value, "To plain copy memory T must be POD!");
    std::memcpy(&dst, &src, sizeof(dst));
  }

}}

#endif  // IROHA_MEMORY_UTILS_HPP
