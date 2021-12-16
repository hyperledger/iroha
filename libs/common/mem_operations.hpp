/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_MEM_OPERATIONS_HPP
#define IROHA_COMMON_MEM_OPERATIONS_HPP

#include <cstring>
#ifdef __linux__
#include "sys/types.h"
#include "sys/sysinfo.h"
#endif//__linux__

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

#ifdef __linux__
  inline uint64_t  getMemoryUsage() {
    struct sysinfo memInfo;
    sysinfo (&memInfo);

    return (memInfo.totalram - memInfo.freeram) * memInfo.mem_unit;
  }
#else//__linux__
  inline uint64_t  getMemoryUsage() {
    return 0ull;
  }
#endif//__linux__

}  // namespace iroha

#endif  // IROHA_COMMON_MEM_OPERATIONS_HPP
