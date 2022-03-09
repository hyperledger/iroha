/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef IROHA_COMMON_MEM_OPERATIONS_HPP
#define IROHA_COMMON_MEM_OPERATIONS_HPP

#include <cstdio>
#include <cstdlib>
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

#ifdef __linux__
  inline uint64_t getMemoryUsage() {
    auto parseLine = [](char const *line) {
      while (!std::isdigit(*line)) ++line;
      return (uint64_t)atoll(line);
    };

    uint64_t result {};
    char line[128];

    std::unique_ptr<FILE, int (*)(FILE *)> file(fopen("/proc/self/status", "r"),
                                                &fclose);

    constexpr char VM_SZ_FIELD[] = "VmSize:";
    auto const vm_size_len = strlen(VM_SZ_FIELD);
    while (fgets(line, sizeof(line), file.get()) != NULL)
      if (strncmp(line, VM_SZ_FIELD, vm_size_len) == 0) {
        result = parseLine(line + vm_size_len);
        break;
      }

    return result * 1024ull;
  }
#else   //__linux__
  inline uint64_t getMemoryUsage() {
    return 0ull;
  }
#endif  //__linux__

}  // namespace iroha

#endif  // IROHA_COMMON_MEM_OPERATIONS_HPP
