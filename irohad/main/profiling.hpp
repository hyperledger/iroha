#ifndef PROFILING_HPP
#define PROFILING_HPP

/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>

namespace iroha {
  namespace debug {

    /// Start profiling. Store results at specified path.
    void startProfiling(std::string path_to_profiles);

    /// Stop profilig and flush the results.
    void stopProfiling();

    /// Save the CPU profile.
    void flushCpuProfile();

    /// Save the memory profile.
    void flushMemProfile();

  }  // namespace debug
}  // namespace iroha

#endif /* PROFILING_HPP */
