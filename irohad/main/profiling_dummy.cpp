/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "main/profiling.hpp"

namespace iroha {
  namespace debug {
    void startProfiling(std::string path_to_profiles) {}
    void stopProfiling() {}
    void flushCpuProfile() {}
    void flushMemProfile() {}
  }  // namespace debug
}  // namespace iroha
