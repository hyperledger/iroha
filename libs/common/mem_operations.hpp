/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_MEM_OPERATIONS_HPP
#define IROHA_COMMON_MEM_OPERATIONS_HPP

#include <cstring>
#include "stdio.h"
#include "stdlib.h"
#include "string.h"

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
  inline uint64_t getMemoryUsage() {
    auto parseLine = [](char *line) {
      while (*line >= '0' && *line <= '9') ++line;
      return (uint64_t)atoll(line);
    };

    uint64_t result = 0ull;
    char line[128];

    FILE *file = fopen("/proc/self/status", "r");
    while (fgets(line, 128, file) != NULL)
      if (strncmp(line, "VmSize:", 7) == 0) {
        result = parseLine(line + 7);
        break;
      }
    fclose(file);

    return result * 1024ull;
  }
#else   //__linux__
  inline uint64_t getMemoryUsage() {
    return 0ull;
  }
#endif  //__linux__

}  // namespace iroha

#endif  // IROHA_COMMON_MEM_OPERATIONS_HPP
